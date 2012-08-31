#ifndef XMLUTIL_H_
#define XMLUTIL_H_

#include <libxml/xmlstring.h>
#include <libxml/tree.h>

xmlChar *getTextFromPath(xmlDocPtr doc, char *xpath);

#define FOR_EACH_NODE(_doc, _path, _node) do { \
	xmlXPathContextPtr _makro_xpathCtx = xmlXPathNewContext(_doc); \
	if (_makro_xpathCtx) { \
	xmlXPathObjectPtr _makro_xpathObj = xmlXPathEvalExpression(BAD_CAST _path, _makro_xpathCtx); \
	if (_makro_xpathObj) { \
	int _makro_i_; \
	if (_makro_xpathObj->nodesetval) for (_makro_i_ = 0; _makro_i_ < _makro_xpathObj->nodesetval->nodeNr; ++_makro_i_) \
	{ _node = _makro_xpathObj->nodesetval->nodeTab[_makro_i_];

#define END_FOR_EACH \
	} } \
	xmlXPathFreeObject(_makro_xpathObj); \
	} \
	xmlXPathFreeContext(_makro_xpathCtx); \
	} while(0)


#endif
