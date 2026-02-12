# pg_auto_revoke_exec

🔐 **pg_auto_revoke_exec** es una Función de seguridad para PostgreSQL que supervisa la creación de funciones y procedimientos, revocando automáticamente el permiso `EXECUTE` del rol `PUBLIC` si está presente en la funcion. Esto refuerza la protección contra accesos no autorizados en entornos multiusuario o productivos.


> ⚠️ **Nota:** Esta función **solo actúa sobre funciones y procedimientos creados recientemente**. No realiza cambios sobre objetos existentes en la base de datos antes de haber sido implementada.


##  ¿Qué hace?

- Monitorea eventos `CREATE FUNCTION` y `CREATE PROCEDURE`.
- Detecta si el rol `PUBLIC` tiene permisos `EXECUTE` sobre el nuevo objeto.
- Revoca automáticamente el permiso inseguro.
- Emite un mensaje informativo si se realiza la acción.


## 🛡️ ¿Por qué usarlo?

Este proyecto ayuda a reforzar la seguridad de tu base de datos:
- Evita exposición accidental de funciones sensibles.
- Impone políticas de acceso mínimas al momento de creación.
- Reduce errores humanos al aplicar restricciones manuales. 

## 📋 Ejemplo de uso

Al ejecutar:

```sql
CREATE OR REPLACE FUNCTION public.demo_fn() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql;
```

Si el rol `PUBLIC` tiene permiso `EXECUTE`, será revocado automáticamente y recibirás un mensaje como:

```
NOTICE: AUDIT: Revocado EXECUTE a PUBLIC en FUNCTION: public.demo_fn()
```

## 🔍 Cómo revisar privilegios `EXECUTE` otorgados a `PUBLIC`

Para verificar si el rol `PUBLIC` tiene acceso a una función específica, puedes ejecutar la siguiente consulta en tu base de datos:

```sql

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
    AND p.proname IN ('demo_fn') -- nombre de la funcion
ORDER BY p.proname;


SELECT  
    DISTINCT
    a.routine_schema 
    ,grantee AS user_name
    ,a.routine_name 
    ,b.routine_type
    ,privilege_type 
FROM information_schema.routine_privileges as a
LEFT JOIN 
    information_schema.routines  as b on a.routine_name=b.routine_name
where  
    NOT a.routine_schema in('pg_catalog','information_schema')  --- Retira este filtro si quieres ver las funciones default de postgres 
    AND a.grantee in('PUBLIC') 
ORDER BY a.routine_schema,a.routine_name ;

```
 
## 📚 Referencia oficial 

Según la [documentación oficial de PostgreSQL](https://www.postgresql.org/docs/current/sql-createfunction.html):

> _"Another point to keep in mind is that by default, execute privilege is granted to PUBLIC for newly created functions [...]. Frequently you will wish to restrict use of a security definer function to only some users. To do that, you must revoke the default PUBLIC privileges and then grant execute privilege selectively."_

Esto significa que **por defecto**, cualquier función o procedimiento creado en PostgreSQL es ejecutable por cualquier usuario del sistema a través del rol `PUBLIC`. Esta política puede abrir la puerta a riesgos de seguridad en entornos productivos, multiusuario o sensibles.


También puedes consultar el resumen oficial de privilegios predeterminados [aquí](https://www.postgresql.org/docs/current/ddl-priv.html#PRIVILEGES-SUMMARY-TABLE).


 
