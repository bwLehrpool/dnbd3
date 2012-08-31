#include "xmlutil.h"
#include <libxml/parser.h>
#include <libxml/xpath.h>


xmlChar *getTextFromPath(xmlDocPtr doc, char *xpath)
{
	xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
	if (xpathCtx == NULL)
		return NULL;
	xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression(BAD_CAST xpath, xpathCtx);
	if (xpathObj == NULL)
	{
		xmlXPathFreeContext(xpathCtx);
		return NULL;
	}
	xmlChar *retval = NULL;
	if (xpathObj->stringval)
		retval = xmlStrdup(xpathObj->stringval);
	else if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0 && xpathObj->nodesetval->nodeTab && xpathObj->nodesetval->nodeTab[0])
	{
		retval = xmlNodeGetContent(xpathObj->nodesetval->nodeTab[0]);
	}
	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	return retval;
}
