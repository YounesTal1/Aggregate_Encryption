#ifndef _Encrypt_h
#define _Encrypt_h  
  

#include <pbc/pbc.h>
#include "Param.h"
#include "SecretKey.h"
  
  
class Encrypt{
public:
  Encrypt();
  Encrypt(element_t& id, element_t& message, element_t *pk, pairing_t& pairing, element_t& g);
  element_t* getCt1();
  element_t& getCt2();

private:
  element_t *ct1;
  element_t ct2;
};
  
  
#endif  

