#include "xmlutil.h"
#include <libxml/parser.h>
#include <libxml/xpath.h>


char *getTextFromPath(xmlDocPtr doc, char *xpath)
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
	char *retval = NULL;
	if (xpathObj->stringval)
		retval = (char*)xmlStrdup(xpathObj->stringval);
	else if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0 && xpathObj->nodesetval->nodeTab && xpathObj->nodesetval->nodeTab[0])
	{
		retval = (char*)xmlNodeGetContent(xpathObj->nodesetval->nodeTab[0]);
	}
	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	return retval;
}
