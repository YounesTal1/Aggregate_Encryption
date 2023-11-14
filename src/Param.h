#ifndef _Param_h
#define _Param_h  
  
#include <pbc/pbc.h>
#include <vector>
  
  
class Param {
public:

    Param();
    Param(const char *pstr);

    pairing_t& getPairing();
    element_t& getGenerator();
    element_t& getAlpha();

    element_t* getPk();
    const char* getPstr();



private:
    pairing_t pairing;
    element_t g; // Generator G1
    element_t alpha;
    element_t* pk;
    const char *pstr;
};  
  
#endif  

