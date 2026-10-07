#include "qv_common.h"

const char *qv_status_str(qv_status_t s)
{
    switch (s) {
    case QV_OK:           return "ok";
    case QV_ERR_PARAM:    return "bad parameter";
    case QV_ERR_MAGIC:    return "bad magic";
    case QV_ERR_VERSION:  return "unsupported version";
    case QV_ERR_SIZE:     return "bad size";
    case QV_ERR_RANGE:    return "address/range violation";
    case QV_ERR_TYPE:     return "wrong image type";
    case QV_ERR_ALG:      return "unsupported algorithm";
    case QV_ERR_HASH:     return "hash mismatch";
    case QV_ERR_CERT:     return "key certificate invalid";
    case QV_ERR_SIG:      return "signature invalid";
    case QV_ERR_ROLLBACK: return "rollback rejected";
    case QV_ERR_STORAGE:  return "secure storage error";
    case QV_ERR_SLOT:     return "no usable slot";
    case QV_ERR_DTB:      return "device tree invalid";
    case QV_ERR_REVOKED:  return "revoked";
    case QV_ERR_NOTRUN:   return "not evaluated";
    default:              return "unknown";
    }
}
