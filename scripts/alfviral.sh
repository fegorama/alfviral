#!/bin/bash


# Variables de configuración
#
ALFRESCO_URL=http://localhost:8080/alfresco
DIR_ROOT=/home/alfresco/alfresco-enterprise-3.3.4/alf_data
USERNAME=alfresco
PASSWD=alfresco
DATABASE=alfresco_enterprise_334
HOST=localhost
PORT=3306

PROG=$0
PROGDIR=`dirname "$PROG"`

SCANRES_FILE=scanres.txt
NODEREFS_FILE=noderefs.txt

# Crea lista de ficheros infectados
#
echo "Creando lista de ficheros infectados..."
CONTENTSTORE=${DIR_ROOT}/contentstore
clamscan -i -r ${CONTENTSTORE} | awk -F: '$1~/.bin/{print "store:/"$1}' | sed s:${CONTENTSTORE}::g > ${PROGDIR}/${SCANRES_FILE}

if [ ! -s ${PROGDIR}/${SCANRES_FILE} ] 
then 
	echo "No hay ficheros infectados."
	exit 0
fi 
 
# Crea lista de NodeRefs de los ficheros
#
echo "Creando referencias NodeRefs de los FUID..."
for FUID in $(cat ${PROGDIR}/${SCANRES_FILE})
do 
	mysql -u${USERNAME} -p${PASSWD} -D${DATABASE} -h${HOST} -P${PORT} --skip-column-names --raw --silent >${PROGDIR}/${NODEREFS_FILE} <<STOP
SELECT alf_node.uuid  
	FROM (alf_node_properties
		INNER JOIN alf_node 
			ON alf_node.id = alf_node_properties.node_id) 
		INNER JOIN alf_qname 
			ON alf_qname.id = alf_node_properties.qname_id
WHERE alf_node_properties.node_id = 
(SELECT alf_node_properties.node_id  
	FROM (alf_content_url
		INNER JOIN alf_node_properties
			ON alf_content_url.id = alf_node_properties.long_value) 
		INNER JOIN alf_qname 
			ON alf_qname.id = alf_node_properties.qname_id 
	WHERE alf_content_url.content_url = '${FUID}'
	AND alf_qname.local_name = 'content')
AND alf_qname.local_name = 'name';	
\q
STOP
done

if [ ! -s ${PROGDIR}/${NODEREFS_FILE} ] 
then 
	echo "¡No se han encontrado referencias a los ficheros!"
	exit 1
fi 

# Lanza las llamadas a Alfresco hacia el webscript
#
echo "Llamando a Alfresco..."
for NODEREF in $(cat ${PROGDIR}/${NODEREFS_FILE}) 
do
	echo "wget ${ALFRESCO_URL}/service/alfviral?nref=${NODEREF}"
done

