

 /*******************************************************************************
 * FUNCIÓN: pg_auto_revoke_exec
 * DESCRIPCIÓN: Garantiza el principio de "mínimo privilegio" revocando 
 * automáticamente el permiso EXECUTE al rol PUBLIC tras un DDL.
 * * MEJORAS DE ARQUITECTURA Y PERFORMANCE:
 * 1. Bucle FOR: Soporta comandos DDL múltiples o scripts masivos (Evita errores).
 * 2. Uso de OID: Identificación por ID numérico interno, no por nombre. 
 * Esto elimina fallos por "sobrecarga" (funciones con igual nombre).
 * 3. Catálogos Nativos: Consulta directa a pg_catalog.pg_proc en lugar de 
 * information_schema, reduciendo drásticamente el consumo de CPU y tiempo.
 * 4. Precisión Quirúrgica: Sin Regex o Parsing de texto que pueda fallar con 
 * caracteres especiales.
 *
 * COMPARATIVA TÉCNICA:
 * - Origen de datos: pg_catalog (Ultra veloz) vs Information_schema (Lento).
 * - Identificación: OID Único (Total precisión) vs Texto/Regex (Frágil).
 * - Estabilidad: Robusto (Procesa N objetos) vs Simple (Falla en scripts masivos).
 *******************************************************************************/



-- DROP FUNCTION pg_auto_revoke_exec();
CREATE OR REPLACE FUNCTION pg_auto_revoke_exec()
RETURNS event_trigger
SET client_min_messages='notice'
AS $$
DECLARE 
    obj record;
    v_has_public_access boolean;
BEGIN
    -- 1. El bucle FOR procesa cada objeto del comando DDL (soporta scripts masivos)
    FOR obj IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands()
    LOOP
        -- 2. Filtramos solo por funciones y procedimientos
        IF obj.object_type IN ('function', 'procedure') THEN
            
            -- 3. VALIDACIÓN DE ALTO RENDIMIENTO
            -- Usamos el OID (objid) que es el índice primario del sistema. 
            -- No hay nada más rápido que esto en PostgreSQL.
            /*SELECT EXISTS (
                SELECT 1 
                FROM pg_catalog.pg_proc p
                WHERE p.oid = obj.objid 
                  AND (
                    p.proacl IS NULL OR -- NULL significa privilegios por defecto (PUBLIC puede)
                    pg_catalog.has_function_privilege('public', p.oid, 'execute')
                  )
            ) INTO v_has_public_access;*/

              -- Versión minimalista
            SELECT pg_catalog.has_function_privilege('public', obj.objid, 'execute') 
            INTO v_has_public_access;

            -- 4. ACCIÓN DIRECTA
            IF v_has_public_access THEN
                -- Usamos object_identity porque ya viene escapado y con tipos de datos
                -- Ejemplo: myschema.mi_func(int4, text)
                EXECUTE format('REVOKE EXECUTE ON %s %s FROM PUBLIC', 
                               obj.object_type, 
                               obj.object_identity);

                -- Notificación técnica limpia
                RAISE NOTICE 'AUDIT: Revocado EXECUTE a PUBLIC en %: %', 
                             upper(obj.object_type), 
                             obj.object_identity;
            END IF;
            
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- DROP EVENT TRIGGER revoke_public_execute;
CREATE EVENT TRIGGER revoke_public_execute
ON ddl_command_end
WHEN TAG IN ('CREATE FUNCTION', 'CREATE PROCEDURE')
EXECUTE FUNCTION pg_auto_revoke_exec();

