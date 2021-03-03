// chequeo de parámetros
if (args.nref == undefined || args.nref.length == 0)
{
    status.code = 400;
    status.message = "Es necesario indicar el nref.";
    status.redirect = true;
}
else
{
    // buscar el documento por su nodeRef
    var nodes = search.luceneSearch("ID\:\"workspace://SpacesStore/" + args.nref + "\"");

    // renombrar el documento
    var name_infected = "";
    name_infected = nodes[0].name;
    if (name_infected.indexOf("_INFECTADO") == -1) 
    {
        nodes[0].name = name_infected + "_INFECTADO";
        nodes[0].save();
        if (logger.isLoggingEnabled())
            logger.log("El documento: " + nodes[0].name + " ha sido renombrado por estar infectado.");
    }
    
    model.name_infected = nodes[0].name;
}
