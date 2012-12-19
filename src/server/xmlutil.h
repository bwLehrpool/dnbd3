#ifndef XMLUTIL_H_
#define XMLUTIL_H_

#include <libxml/xmlstring.h>
#include <libxml/tree.h>
#include <inttypes.h>

char *getTextFromPath(xmlDocPtr doc, char *xpath);
char createXmlDoc(xmlDocPtr *doc, xmlNodePtr* root, char* rootName);

// Two macros to iterate over a node list

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

// Two macros to deal with temporary pointers

#define NUM_POINTERS_IN_LIST 20
#define NEW_POINTERLIST \
	void *_makro_ptrlist[NUM_POINTERS_IN_LIST]; \
	int _makro_usedcount = 0

#define FREE_POINTERLIST do { \
	int _makro_i_; \
	for (_makro_i_ = 0; _makro_i_ < _makro_usedcount; ++_makro_i_) { \
		xmlFree(_makro_ptrlist[_makro_i_]); \
	} } while(0)

// Macro to get a node property with automatic pointer handling (see two macros above)

#define XML_GETPROP(_node, _name) (char*)(_makro_ptrlist[(_makro_usedcount >= NUM_POINTERS_IN_LIST ? 0 : _makro_usedcount++)] = xmlGetNoNsProp(_node, BAD_CAST _name))

// Inline function to print a numeric value to a char buffer and add as property

static inline void xmlAddDecimalProp(int64_t value, xmlNodePtr node, char* name)
{
	char strbuffer[100];
	sprintf(strbuffer, "%" PRId64, value);
	xmlNewProp(node, BAD_CAST name, BAD_CAST strbuffer);
}

#endif
