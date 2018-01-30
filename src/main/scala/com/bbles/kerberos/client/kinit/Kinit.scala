package com.bbles.kerberos.client.kinit

import java.io.{File, IOException}
import java.util
import javax.security.auth.kerberos.KeyTab

import com.bbles.kerberos.client.KerberosUtils.{debug, setOptions}
import sun.security.krb5.internal.ccache.{Credentials, CredentialsCache}
import sun.security.krb5.internal.{HostAddresses, KDCOptions}
import sun.security.krb5.{Config, KrbAsReqBuilder, PrincipalName}
import sun.security.util.Password

class Kinit {
  def kinit(args: Array[String], loginContext: String): Credentials = {
    var options: KinitOptions = new KinitOptions()
    if (args == null || args.length == 0) {
      options = new KinitOptions;
    } else {
      options = KinitOptions(args);
    }
    var princName: String = null;
    val principal: PrincipalName = options.getPrincipal;
    if (principal != null) {
      princName = principal.toString();
    }
    var builder: KrbAsReqBuilder = null;

    debug("Principal is " + principal);

    var psswd: Array[Char] = options.password;
    val useKeytab: Boolean = options.useKeytabFile;
    if (!useKeytab) {
      if (princName == null) {
        throw new IllegalArgumentException
        (" Can not obtain principal name");
      }
      if (psswd == null) {
        debug("Password for " + princName + ":");
        System.out.flush();
        psswd = Password.readPassword(System.in);

        debug(">>> Kinit console input " + new String(psswd));
      }
      builder = new KrbAsReqBuilder(principal, psswd);
    } else {
      debug(">>> Kinit using keytab");
      if (princName == null) {
        throw new IllegalArgumentException
        ("Principal name must be specified.");
      }
      val ktabName: String = options.keytab_file;
      if (ktabName != null) {
        debug(">>> Kinit keytab file name: " + ktabName);
      }

      builder = new KrbAsReqBuilder(
        principal,
        if (ktabName == null) KeyTab.getInstance() else KeyTab.getInstance(new File(ktabName))
      );
    }

    val opt: KDCOptions = new KDCOptions();
    setOptions(KDCOptions.FORWARDABLE, options.forwardable, opt);
    setOptions(KDCOptions.PROXIABLE, options.proxiable, opt);

    builder.setOptions(opt);

    var realm: String = options.getKDCRealm;
    if (realm == null) {
      realm = Config.getInstance().getDefaultRealm();
    }

    debug(">>> Kinit realm name is " + realm);


    val sname: PrincipalName = PrincipalName.tgsService(realm, realm);
    builder.setTarget(sname);

    debug(">>> Creating KrbAsReq")

    if (options.getAddressOption)
      builder.setAddresses(HostAddresses.getLocalAddresses());

    builder.action();

    val credentials: sun.security.krb5.internal.ccache.Credentials = builder.getCCreds();
    builder.destroy();

    // we always create a new cache and store the ticket we get
    debug(s">> Using the cache file: ${options.cachename}")
    val cache: CredentialsCache = CredentialsCache.create(principal, options.cachename);
    if (cache == null) {
      throw new IOException("Unable to create the cache file " + options.cachename);
    }
    cache.update(credentials);
    cache.save();

    if (options.password == null) {
      // Assume we're running interactively
      debug("New ticket is stored in cache file " + options.cachename);
    } else {
      util.Arrays.fill(options.password, '0');
    }

    // clear the password
    if (psswd != null) {
      util.Arrays.fill(psswd, '0');
    }
    cache.getCreds(options.getPrincipal)
  }

}
