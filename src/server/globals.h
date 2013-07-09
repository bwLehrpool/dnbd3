#ifndef _GLOBALS_H_
#define _GLOBALS_H_

/**
 * Base directory where all images are stored in. Will always have a trailing slash
 */
extern char *_basePath;

/**
 * Whether or not simple *.vmdk files should be treated as revision 1
 */
extern int _vmdkLegacyMode;

#endif /* GLOBALS_H_ */
