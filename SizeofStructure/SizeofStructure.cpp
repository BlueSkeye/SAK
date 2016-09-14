#include "stdafx.h"
#include <Setupapi.h>

int main()
{
	int result = sizeof(SP_DRVINFO_DATA_W);
	result = offsetof(SP_DRVINSTALL_PARAMS, Flags);
    return 0;
}

