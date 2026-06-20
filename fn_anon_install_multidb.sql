DO $$
DECLARE
    -- =========================================================================
    -- CONFIGURACIÓN DE PARÁMETROS DE DESPLIEGUE
    -- =========================================================================
    -- v_dbs_to_include: Usa ARRAY['all'] para procesar todo, o especifica ARRAY['db1', 'db2']
    v_dbs_to_include TEXT[] := ARRAY['all'];  
    
    -- v_dbs_to_exclude: Usa ARRAY['none'] para no omitir ninguna, o especifica ARRAY['db_segura', 'postgres']
    v_dbs_to_exclude TEXT[] := ARRAY['template0']; 

    -- Variables de control de infraestructura
    v_db             TEXT;
    v_socket         TEXT;
    v_port           TEXT;
    v_conn_str       TEXT;
    v_db_conn_name   TEXT := 'deploy_event_trigger_conn';
    v_error_msg      TEXT;
    v_created_dblink BOOLEAN := FALSE;
    v_deploy_sql     TEXT;
BEGIN
    -- 1. Inicializar entorno y verbosidad
    SET client_min_messages = notice;
    RAISE NOTICE '=========================================================================';
    RAISE NOTICE 'INICIANDO DESPLIEGUE MASIVO DE: pg_auto_revoke_exec() & EVENT TRIGGER';
    RAISE NOTICE '=========================================================================';

    -- 2. Gestión dinámica de dblink
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'dblink') THEN
        CREATE EXTENSION dblink;
        v_created_dblink := TRUE;
        RAISE NOTICE '>> [ENTORNO] Extensión dblink creada temporalmente para el despliegue.';
    END IF;

    -- 3. Resolver dirección de sockets locales y puerto activo
    SELECT replace(setting, ' ', '') INTO v_socket FROM pg_settings WHERE name = 'unix_socket_directories';
   /*
    -- Si existen múltiples sockets mapeados por el OS, extraemos el primero
    IF v_socket LIKE '%,%' THEN
        v_socket := split_part(v_socket, ',', 1);
    END IF;*/
    SELECT setting INTO v_port FROM pg_settings WHERE name = 'port';

    -- 4. Definición empaquetada del código fuente a inyectar en los destinos
    v_deploy_sql := $DEPLOY$
        CREATE OR REPLACE FUNCTION public.pg_auto_revoke_exec()
        RETURNS event_trigger
        SET client_min_messages='notice'
        SET search_path = public, pg_temp
        AS $CODE$
        DECLARE 
            v_obj record;
            v_has_public_access boolean;
            v_show_notice boolean := true; 
        BEGIN
            -- 1. El bucle FOR procesa cada objeto del comando DDL
            FOR v_obj IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands()
            LOOP
                -- 2. Filtramos solo por funciones y procedimientos
                IF v_obj.object_type IN ('function', 'procedure') THEN
                                   
                    -- 3. Validación rápida de privilegios para PUBLIC
                    SELECT pg_catalog.has_function_privilege('public', v_obj.objid, 'execute') 
                    INTO v_has_public_access;

                    -- 4. ACCIÓN DIRECTA
                    IF v_has_public_access THEN
                    
                        -- Ejecución del REVOKE
                        EXECUTE pg_catalog.format('REVOKE EXECUTE ON %s %s FROM PUBLIC', 
                                       v_obj.object_type, 
                                       v_obj.object_identity);

                        -- Notificación condicional
                        IF v_show_notice THEN
                            RAISE NOTICE 'AUDIT: Revocado EXECUTE a PUBLIC en %: %', 
                                       upper(v_obj.object_type), 
                                       v_obj.object_identity;
                        END IF;
                    END IF;
                    
                END IF;
            END LOOP;
        END;
        $CODE$ LANGUAGE plpgsql;

        -- Limpieza preventiva del trigger en el destino
        DROP EVENT TRIGGER IF EXISTS revoke_public_execute;

        -- Creación del Event Trigger asociado
        CREATE EVENT TRIGGER revoke_public_execute
        ON ddl_command_end
        WHEN TAG IN ('CREATE FUNCTION', 'CREATE PROCEDURE')
        EXECUTE FUNCTION public.pg_auto_revoke_exec();
    $DEPLOY$;

    -- 5. Iteración con filtrado matricial de Bases de Datos
    FOR v_db IN 
        SELECT datname 
        FROM pg_database 
        WHERE 
            -- Regla de Inclusión: Si es 'all' incluye todo (incluyendo templates). Si no, valida la lista.
            (EXISTS (SELECT 1 FROM unnest(v_dbs_to_include) i WHERE LOWER(i) = 'all') OR datname = ANY(v_dbs_to_include))
            -- Regla de Exclusión: Si la lista contiene la DB actual y NO es 'none', la deja fuera.
            AND NOT (datname = ANY(v_dbs_to_exclude) AND NOT EXISTS (SELECT 1 FROM unnest(v_dbs_to_exclude) e WHERE LOWER(e) = 'none'))
    LOOP
        -- Construcción del string de conexión local por sockets de confianza
        v_conn_str := format('dbname=%L host=%s port=%s user=postgres', v_db, v_socket, v_port);
        
        BEGIN
            -- Intento de conexión remota
            PERFORM dblink_connect(v_db_conn_name, v_conn_str);
            
            -- Inyección de la función y del trigger
            PERFORM dblink_exec(v_db_conn_name, v_deploy_sql);
            
            -- Cierre exitoso de sesión remota
            PERFORM dblink_disconnect(v_db_conn_name);
            
            RAISE NOTICE '>> [ÉXITO] Sincronizado e instalado en base de datos: %', v_db;
            
        EXCEPTION WHEN OTHERS THEN
            -- Captura del error específico de la DB actual (Ej. si template0 rechaza conexiones de red)
            GET STACKED DIAGNOSTICS v_error_msg = MESSAGE_TEXT;
            RAISE WARNING '>> [ERROR] No se pudo instalar en la base de datos "%" | Razón: %', v_db, v_error_msg;
            
            -- Garantizar la liberación del canal dblink si la sesión se quedó abierta
            IF dblink_get_connections() @> ARRAY[v_db_conn_name] THEN
                PERFORM dblink_disconnect(v_db_conn_name);
            END IF;
        END;
    END LOOP;

    -- 6. Limpieza final de la casa
    IF v_created_dblink THEN
        DROP EXTENSION dblink;
        RAISE NOTICE '>> [ENTORNO] Extensión dblink temporal removida con éxito.';
    END IF;

    RAISE NOTICE '=========================================================================';
    RAISE NOTICE 'DESPLIEGUE MASIVO PROCESADO COMPLETAMENTE';
    RAISE NOTICE '=========================================================================';

EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_error_msg = MESSAGE_TEXT;
    IF dblink_get_connections() @> ARRAY[v_db_conn_name] THEN
        PERFORM dblink_disconnect(v_db_conn_name);
    END IF;
    RAISE EXCEPTION 'Fallo crítico global durante la orquestación: %', v_error_msg;
END $$;
