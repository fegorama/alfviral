/*
 * alfviral is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * alfviral is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * scanFolder
 * Lanza la funciÃ³n recursiva de escaneo.
 * 
 * @param folder_scan
 * @param p
 */
function ScanFolder(folder_scan, p)
{
    logger.log("============");
    logger.log(" ScanFolder ")
    logger.log("============");
    
    logger.log("Scanning from: " + folder_scan.replace(companyhome.name + "/", ""));
    logger.log("Â¿Recursive? " + (p.equals("r") ? "Si" : "No"));
    
    scanFolderRun(folder_scan, p);
}

/*
 * scanFolderRun
 * FunciÃ³n de escaneo que usa un folder inicial y 
 * el parÃ¡metro p que si es "r" la harÃ¡ recursiva.
 * 
 * @param folder_scan
 * @param p
 */
function scanFolderRun(folder_scan, p)
{
    var success = false;
    var files_scan = companyhome.children;

    /*
     * Comprueba si es la raÃ­z Company Home, si no
     * hay que eliminar la cadena de Company Home (Espacio de empresa)
     * para que localice correctament el nodeRef.
     */
    if (folder_scan.replace(companyhome.name, "").length > 0)
    {
        files_scan = companyhome.childByNamePath(folder_scan.replace(companyhome.name + "/", "")).children;
    }

    /*
     * Si se encuentra la carpeta...
     */
    if (files_scan)
    {
        /*
         * Recorrido...
         */
        for ( var file_scan in files_scan)
        {
            /*
             * Si es un documento se llama a la acciÃ³n de escaneo.
             */
            if (files_scan[file_scan].isDocument)
            {
                logger.log("Escaneando: " + files_scan[file_scan].displayPath + "/" + files_scan[file_scan].name);
                actions.create("alfviral.virusscan.action").execute(files_scan[file_scan]);
            }
            /*
             * Si es una carpeta y estÃ¡ activada la recursividad se llama a sÃ­ misma.
             */
            else
                if (files_scan[file_scan].isContainer && p == "r")
                {
                    logger.log("Entrando en: " + files_scan[file_scan].displayPath + "/" + files_scan[file_scan].name);
                    scanFolderRun(files_scan[file_scan].displayPath + "/" + files_scan[file_scan].name, "r");
                }
        }
        success = true;
    }
    else
    {
        logger.log("No se ha encontrado la carpeta para escanear.");
    }

    return success;
}
