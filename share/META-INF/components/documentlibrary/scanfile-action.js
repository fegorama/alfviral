/**
 * DocumentList "ScanFile" action
 * 
 * @namespace Alfresco
 * @class Alfresco.DocumentList
 */
(function()
{
   /**
* Name of the script below Data Dictionary/Scripts to execute, e.g. "my test script.js"
*/
   var JSCRIPT_NAME = "scanfile.post.js";
   
   /**
* Base name for message bundle strings used for success/failure messages. Messages should
* be defined in your own global message bundle.
*/
   var MSG_BASE = "scanfile";
   
   /**
* Name of the JavaScript function to be added to the Alfresco.doclib.Actions prototype,
* e.g. onActionMyTestScript
*/
   var FN_NAME = "onActionScanFile";
   
   /**
* Execute a specific script against a document.
*
* @method onActionScanfile
* @param file {object} Object literal representing one or more file(s) or folder(s) to be actioned
*/
   YAHOO.Bubbling.fire("registerAction",
   {
      actionName: FN_NAME,
      fn: function DL_onActionScanFile(file)
      {
          var nodeRef = new Alfresco.util.NodeRef(file.nodeRef);
          
          this.modules.actions.genericAction(
          {
             success:
             {
                event:
                {
                   name: "metadataRefresh"
                },
                message: this.msg("message." + MSG_BASE + ".success", file.displayName)
             },
             failure:
             {
                message: this.msg("message." + MSG_BASE + ".failure", file.displayName)
             },
             webscript:
             {
                name: "scanfile/site/{site}/{container}",
                method: Alfresco.util.Ajax.POST,
                params:
                {
    	            site: this.options.siteId,
    	            container: this.options.containerId
                }
             },
             config:
             {
                requestContentType: Alfresco.util.Ajax.JSON,
                dataObj:
                {
                	nodeRefs: [file.nodeRef]
                }
             }
          });
       }
   });
})();
