
CREATE OR REPLACE FUNCTION pg_auto_revoke_exec()
RETURNS event_trigger
SET client_min_messages='notice'
AS $$
DECLARE 
	v_object_type text;
	v_schema_name text;
	v_object_identity text;
	v_execute text;
	v_obj_name_clear text;

	v_query_funpro text;
	v_stt_result boolean ; 
	
BEGIN
	
	--- Obtiene los datos del objeto, como schema, nombre y tipo
	SELECT object_type,schema_name,object_identity  INTO v_object_type,v_schema_name,v_object_identity FROM pg_catalog.pg_event_trigger_ddl_commands();

	-- Limpia la variable v_object_identity ya que trae el esquema y los parametros 
	v_obj_name_clear := substring(v_object_identity FROM '\.([a-zA-Z0-9_]+)\(') ;

	-- prepara la query para validar  si el usuario PUBLIC  tiene permiso EXECUTE en la funcion o procedimiento 
	v_query_funpro =  format( E'
		SELECT  
			true
		FROM information_schema.routine_privileges as a
		LEFT JOIN 
			information_schema.routines  as b on a.routine_name=b.routine_name and a.routine_schema = b.routine_schema
		where  
			 a.grantee = \'PUBLIC\' 
			 and lower(b.routine_type) = %L
			 and a.routine_schema  = %L
			 and a.routine_name  =  %L ' , v_object_type , v_schema_name , v_obj_name_clear   )  ;
	
	-- Ejecuta la query 
	EXECUTE v_query_funpro into v_stt_result ;

	-- Valida si obtuvo resultados la query ejecutada 
	IF v_stt_result THEN 

		v_execute := format('REVOKE EXECUTE ON %s  %s FROM PUBLIC' ,v_object_type,v_object_identity);
		EXECUTE v_execute;
		RAISE NOTICE E'\n\n /********** Por SEGURIDAD Se realizo el REVOKE EXECUTE al role PUBLIC **********\\  \n\t%: %\n\n ',upper(v_object_type),v_object_identity;
	
	END IF;
	
END;
$$ LANGUAGE plpgsql;




CREATE EVENT TRIGGER revoke_public_execute
ON ddl_command_end
WHEN TAG IN ('CREATE FUNCTION','CREATE PROCEDURE')
EXECUTE FUNCTION  pg_auto_revoke_exec();

