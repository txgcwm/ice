#ifndef __PUBLIC_PUB_H__
#define __PUBLIC_PUB_H__


enum
{
    TYPE_ATRR_UNKNOWN = 0x00,

    TYPE_ATTR_GUID_OFFER,
    TYPE_ATTR_GUID_ANSWER,
    TYPE_ATTR_HOLE_INFO,
};

enum
{
    MSG_TYPE_UNKNOWN = 0x00,

    MSG_TYPE_REGISTER,
    MSG_TYPE_REGISTER_RESPONSE,    

    MSG_TYPE_TRAVERSAL_REQUEST,
    MSG_TYPE_TRAVERSAL_RESPONSE,

};

enum
{
    ERROR_SUCCESS  =0x00,

    ERROR_PEER_INFO_NOT_FOUND,
};


#endif
