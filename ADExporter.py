import ldap
from ldap.controls import SimplePagedResultsControl

# helper function to try to decode results if possible
def try_decode(value):
    if isinstance(value, bytes):
        try:
            value = value.decode()
        except:
            # sometimes, we can't decode bytes to str
            # so we just ignore and return it as is
            pass

    return value

def query_activedirectory(uri, bindDN, bindPW, baseDN, filterstr='(objectClass=*)', attrlist=None, timeout=-1, pagesize=1000, decodeBytes=True):

    con = ldap.initialize(uri, bytes_mode=False)
    con.protocol_version = ldap.VERSION3
    con.set_option(ldap.OPT_REFERRALS,0)  # required for AD authentication
    con.simple_bind_s(bindDN, bindPW)

    # optional, but reduce the number of supported control, since only this one will be parsed
    known_ldap_resp_ctrls = {
        SimplePagedResultsControl.controlType: SimplePagedResultsControl,
    }

    # instantiate the control that will make the paged results
    # it carries the page cookie (initially empty, to request the first page)
    req_ctrl = SimplePagedResultsControl(
        criticality=True,
        size=pagesize,
        cookie=''
    )

    while True:
        # query next page, asynchronous
        msgid = con.search_ext(
            baseDN,
            ldap.SCOPE_SUBTREE,
            filterstr,
            attrlist=attrlist,
            serverctrls=[req_ctrl],
        )

        # get the page results
        rtype, rdata, rmsgid, serverctrls = con.result3(
            msgid,
            timeout=timeout,
            resp_ctrl_classes=known_ldap_resp_ctrls,
        )

        # just assure the rtype is ok
        # we don't really expect other result, but RES_SEARCH_RESULT
        if rtype == ldap.RES_SEARCH_RESULT:
            # process results
            for dn, attrs in rdata:
                if dn:
                    if decodeBytes:
                        attrs = {
                            k: [try_decode(i) for i in attrs[k]]
                            for k in attrs
                        }

                    # yield the value
                    yield dn, attrs

            # search for the requested server control
            pctrls = [
                c
                for c in serverctrls
                if c.controlType == SimplePagedResultsControl.controlType
            ]

            if not pctrls:
                # pctrls is empty, so the control was not found
                # most probably, the control it is not supported by the server
                # I'll break here and stop silently, but you may want to raise an exception
                #raise Exception('Warning:  Server ignores RFC 2696 control, so paging is not possible.')
                break
            else:
                # pctrls is not empty, so the control is there
                req_ctrl.cookie = pctrls[0].cookie

            if not req_ctrl.cookie:
                # cookie is empty, so there is no more pages to fetch
                # our job is done, just break the loop
                break
        else:
            # unexpected rtype
            # I'll break here and stop silently, but you may want to raise an exception
            break

    # free resources
    con.unbind_ext_s()

if __name__ == "__main__":

    # the function returns a generator, so it won't fetch anything yet
    response = query_activedirectory(
        uri="ldap://35.208.84.191:389",
        bindDN="cn=Administrator,cn=Users,dc=corp,dc=unfinishedlife,dc=org",
        bindPW="!33B0rn0t33b",
        baseDN="cn=Users,dc=corp,dc=unfinishedlife,dc=org",
        filterstr="(objectClass=user)",
        attrlist=["sn", "givenName","memberOf"],  # None to fetch all attributes
        timeout=-1,    # wait indefinitely
        pagesize=1000  # this is an internal parameter that says how many records do you want to fetch per request
        # it doesn't change the result, since pages are fetched as needed
        # by default, the max number of records allowed by AD is 1000
        # so if you request more than 1000 records, it will return 1000
    )

    # fetch and display the results
    for dn, attrs in response:
        print(dn)
        print(attrs)
