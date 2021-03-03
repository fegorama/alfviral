<import resource="classpath:/alfresco/templates/webscripts/org/alfresco/slingshot/documentlibrary/action/action.lib.js">

/**
 * ScanFile multiple files action
 * @method POST
 */

/**
 * Entrypoint required by action.lib.js
 *
 * @method runAction
 * @param p_params {object} Object literal containing files array
 * @return {object|null} object representation of action results
 */
function runAction(p_params)
{
   var results = [];
   var files = p_params.files;
   var file, fileNode, result, nodeRef;

   if (!files || files.length == 0)
   {
      status.setCode(status.STATUS_BAD_REQUEST, "¿files?");
      return;
   }

   for (file in files)
   {
      nodeRef = files[file];
      result =
      {
         nodeRef: nodeRef,
         action: "scanfile",
         success: false
      }

      try
      {
         fileNode = search.findNode(nodeRef);
         if (fileNode === null)
         {
            result.id = file;
            result.nodeRef = nodeRef;
            result.success = false;
         }
         else
         {
            result.id = fileNode.name;
            result.type = fileNode.isContainer ? "folder" : "document";
// TODO poner try...catch
            actions.create("alfviral.virusscan.action").execute(fileNode); 
            if (fileNode.hasAspect("infected"))
            {
                result.infected = true;
            }
            result.success = true;
         }
      }
      catch (e)
      {
         result.id = file;
         result.nodeRef = nodeRef;
         result.success = false;
      }

      results.push(result);
   }

   return results;
}

/* Bootstrap action script */
main();
