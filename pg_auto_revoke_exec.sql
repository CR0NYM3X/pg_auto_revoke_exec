

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
    v_obj record;
    v_has_public_access boolean;
    -- ==========================================
    -- CONFIGURACIÓN: TRUE para mostar los mensajes de aviso, FALSE para modo silencioso
    v_show_notice boolean := true; 
    -- ==========================================
BEGIN
    -- 1. El bucle FOR procesa cada objeto del comando DDL (soporta scripts masivos)
    FOR v_obj IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands()
    LOOP
        
         -- 2. Filtramos solo por funciones y procedimientos
        IF v_obj.object_type IN ('function', 'procedure') THEN
                       
            -- En caso de errores en validaciones en versiones viejitas usar esta
            /*SELECT EXISTS (
                SELECT 1 
                FROM pg_catalog.pg_proc p
                WHERE p.oid = v_obj.objid 
                  AND (
                    p.proacl IS NULL OR -- NULL significa privilegios por defecto (PUBLIC puede)
                    pg_catalog.has_function_privilege('public', p.oid, 'execute')
                  )
            ) INTO v_has_public_access;*/

            -- 3. Validación rápida de privilegios para PUBLIC
            SELECT pg_catalog.has_function_privilege('public', v_obj.objid, 'execute') 
            INTO v_has_public_access;

            -- 4. ACCIÓN DIRECTA
            IF v_has_public_access THEN
            
                -- Ejecución del REVOKE
                EXECUTE format('REVOKE EXECUTE ON %s %s FROM PUBLIC', 
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
$$ LANGUAGE plpgsql;

-- DROP EVENT TRIGGER revoke_public_execute;
CREATE EVENT TRIGGER revoke_public_execute
ON ddl_command_end
WHEN TAG IN ('CREATE FUNCTION', 'CREATE PROCEDURE')
EXECUTE FUNCTION pg_auto_revoke_exec();

