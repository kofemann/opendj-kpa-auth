This is an OpenDJ authentication policy plugin for users whose credentials
are managed by an external Kerberos realm.

Requirements
------------
  1. Java sdk 1.6 or above
  2. Apache ANT
  3. OpenDJ installation

Build and Install
----------------
  1. build and install the extention

    ```$ ant -Dopends.install.dir=/path/to/opendj install```

  2. restart the server

    ```$ bin/stop-ds --restart```

  3. configure the pass-through for kerberos

    ```$ bin/dsconfig -X create-password-policy \
       --type kerberos-pass-through \
       --policy-name "Krb5 Pass Through" \
       --set krb5-realm:EXAMPLE.COM \
       --set mapped-attribute=uid```

  4. assign pass-through authentication to users

    You assign authentication policies in the same way as you assign password
    policies, by using the ***ds-pwp-password-policy-dn*** attribute:
    ```ds-pwp-password-policy-dn: cn=Krb5 Pass Through,cn=Password Policies,cn=config```

    Users depending on pass through authentication no longer need a local password policy,
    as they no longer authenticate locally.

More Info
---------
[Configuring Pass Through Authentication][1]

  [1]: http://opendj.forgerock.org/opendj-server/doc/admin-guide/index/chap-pta.html
