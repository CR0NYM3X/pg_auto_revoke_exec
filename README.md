# pg_auto_revoke_exec

🔐 **pg_auto_revoke_exec** es una Función de seguridad para PostgreSQL que supervisa la creación de funciones y procedimientos, revocando automáticamente el permiso `EXECUTE` del rol `PUBLIC` si está presente en la funcion. Esto refuerza la protección contra accesos no autorizados en entornos multiusuario o productivos.


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
CREATE FUNCTION demo_fn() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql;
```

Si el rol `PUBLIC` tiene permiso `EXECUTE`, será revocado automáticamente y recibirás un mensaje como:

```
NOTICE: ********** Por SEGURIDAD Se realizo el REVOKE EXECUTE al role PUBLIC **********
         FUNCTION: schema_name.demo_fn()
```

## 🔍 Cómo revisar privilegios `EXECUTE` otorgados a `PUBLIC`

Para verificar si el rol `PUBLIC` tiene acceso a una función específica, puedes ejecutar la siguiente consulta en tu base de datos:

```sql
SELECT DISTINCT
    a.routine_schema,
    grantee AS user_name,
    a.routine_name,
    b.routine_type,
    privilege_type
FROM information_schema.routine_privileges AS a
LEFT JOIN information_schema.routines AS b
    ON a.routine_name = b.routine_name
WHERE
    NOT a.routine_schema IN ('pg_catalog', 'information_schema')  -- Retira este filtro si quieres incluir funciones del sistema
    AND a.grantee = 'PUBLIC'
    AND a.routine_name = 'demo_fn'
ORDER BY a.routine_schema, a.routine_name;
```
 
## 📚 Referencia oficial 

Según la [documentación oficial de PostgreSQL](https://www.postgresql.org/docs/current/sql-createfunction.html):

> _"Another point to keep in mind is that by default, execute privilege is granted to PUBLIC for newly created functions [...]. Frequently you will wish to restrict use of a security definer function to only some users. To do that, you must revoke the default PUBLIC privileges and then grant execute privilege selectively."_

Esto significa que **por defecto**, cualquier función o procedimiento creado en PostgreSQL es ejecutable por cualquier usuario del sistema a través del rol `PUBLIC`. Esta política puede abrir la puerta a riesgos de seguridad en entornos productivos, multiusuario o sensibles.


También puedes consultar el resumen oficial de privilegios predeterminados [aquí](https://www.postgresql.org/docs/current/ddl-priv.html#PRIVILEGES-SUMMARY-TABLE).


 
