--- ============================================================================
--- 1. SET DE PRUEBAS: CREACIÓN DE FUNCIONES
--- Estos comandos dispararán el Event Trigger para cada objeto.
--- ============================================================================

-- Caso 1: Función simple
CREATE OR REPLACE FUNCTION public.fn_test_estandar() 
RETURNS text AS $$ BEGIN RETURN 'Acceso concedido'; END; $$ LANGUAGE plpgsql;

-- Caso 2: Sobrecarga (Mismo nombre, diferentes argumentos)
-- Esto valida que el Trigger use OID y no solo el nombre.
CREATE OR REPLACE FUNCTION public.fn_test_sobrecarga(val int) 
RETURNS int AS $$ BEGIN RETURN val * 1; END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.fn_test_sobrecarga(val int, factor int) 
RETURNS int AS $$ BEGIN RETURN val * factor; END; $$ LANGUAGE plpgsql;

-- Caso 3: Seguridad (Nombre con caracteres especiales e intento de inyección)
-- Esto valida que el comando REVOKE sea robusto ante nombres maliciosos.
CREATE OR REPLACE FUNCTION public."fn_test; DROP TABLE usuarios; --"() 
RETURNS boolean AS $$ BEGIN RETURN true; END; $$ LANGUAGE plpgsql;


--- ============================================================================
--- 2. QUERY DE VERIFICACIÓN DE PRIVILEGIOS
--- Esta consulta busca específicamente si PUBLIC tiene permisos de ejecución.
--- ============================================================================



SELECT 
    n.nspname AS esquema,
    p.proname AS nombre_funcion,
    pg_get_function_arguments(p.oid) AS argumentos,
    CASE 
        WHEN p.proacl IS NULL THEN 'Defecto (Suele incluir PUBLIC)'
        ELSE array_to_string(p.proacl, ', ') 
    END AS lista_privilegios,
    -- Esta columna es la prueba de fuego:
    pg_catalog.has_function_privilege('public', p.oid, 'execute') AS public_puede_ejecutar
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON p.pronamespace = n.oid
WHERE n.nspname = 'public' 
  AND p.proname IN ('fn_test_estandar', 'fn_test_sobrecarga', 'fn_test; DROP TABLE usuarios; --')
ORDER BY p.proname;






/* NOTA: Si el trigger funcionó, la columna 'public_puede_ejecutar' debe decir FALSE 
y en 'lista_privilegios' NO debe aparecer la sigla '=X/' (que representa a PUBLIC).
*/


--- ============================================================================
--- 3. PRUEBA DE CAMPO (SIMULACIÓN DE USUARIO)
--- ============================================================================
/*
-- Ejecuta esto para probar como un usuario sin privilegios:
CREATE ROLE usuario_anonimo;
SET ROLE usuario_anonimo;

SELECT public.fn_test_estandar(); -- Debería lanzar: ERROR: permission denied

RESET ROLE;
DROP ROLE usuario_anonimo;
*/


--- ============================================================================
--- 4. LIMPIEZA (DROP)
--- Comandos comentados para borrar las pruebas después de validar.
--- ============================================================================

-- DROP FUNCTION IF EXISTS public.fn_test_estandar();
-- DROP FUNCTION IF EXISTS public.fn_test_sobrecarga(int);
-- DROP FUNCTION IF EXISTS public.fn_test_sobrecarga(int, int);
-- DROP FUNCTION IF EXISTS public."fn_test; DROP TABLE usuarios; --"();
