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


char createXmlDoc(xmlDocPtr *doc, xmlNodePtr* root, char* rootName)
{
	*doc = xmlNewDoc(BAD_CAST "1.0");
	if (*doc == NULL)
		return 0;
	*root = xmlNewNode(NULL, BAD_CAST rootName);
	if (*root == NULL)
	{
		xmlFreeDoc(*doc);
		return 0;
	}
	xmlDocSetRootElement(*doc, *root);
	return 1;
}
