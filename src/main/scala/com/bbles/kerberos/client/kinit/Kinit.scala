package com.bbles.kerberos.client.kinit

import java.io.{File, IOException}
import java.util
import javax.security.auth.kerberos.KeyTab

import com.bbles.kerberos.client.KerberosLogger
import sun.security.krb5.internal.ccache.{Credentials, CredentialsCache}
import sun.security.krb5.internal.{HostAddresses, KDCOptions}
import sun.security.krb5.{Config, KrbAsReqBuilder, PrincipalName}
import sun.security.util.Password

object Kinit extends KerberosLogger {
  def kinit(args: Array[String], loginContext: String): Credentials = {

    // Parse the arguments
    var options: KinitOptions = KinitOptions(args)

    val principal: PrincipalName = options.getPrincipal;

    // We build the request
    var builder: KrbAsReqBuilder = null;

    debug(">> Principal is : " + principal);

    var psswd: Array[Char] = options.password;
    val useKeytab: Boolean = options.useKeytabFile;
    if (!useKeytab) {
      if (principal == null) {
        throw new IllegalArgumentException
        (" Can not obtain principal name");
      }
      if (psswd.isEmpty) {
        System.out.flush();
        psswd = Password.readPassword(System.in);
        debug(">>> Kinit console input " + new String(psswd));
      }
      builder = new KrbAsReqBuilder(principal, psswd);
    } else {
      debug(">>> Kinit using keytab");
      if (principal == null) {
        throw new IllegalArgumentException("Principal name must be specified.");
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
    setOptions(KDCOptions.RENEW, options.renewable, opt)
    setOptions(KDCOptions.FORWARDABLE, options.forwardable, opt);
    setOptions(KDCOptions.PROXIABLE, options.proxiable, opt);

    builder.setOptions(opt);

    var realm: String = options.getKDCRealm;

    debug(realm)

    if (realm == null) {
      realm = Config.getInstance().getDefaultRealm();
    }

    debug(">>> Kinit realm name is " + realm);


    val sname: PrincipalName = PrincipalName.tgsService(realm, realm);

    debug(s"Getting the tgs: ${sname.toString}")
    builder.setTarget(sname);

    debug(">>> Creating KrbAsReq")

    if (options.getAddressOption)
      builder.setAddresses(HostAddresses.getLocalAddresses());

    builder.action();

    val credentials: sun.security.krb5.internal.ccache.Credentials = builder.getCCreds();
    builder.destroy();

    debug(s">> Using the cache file: ${options.cachename}")
    val cache: CredentialsCache = CredentialsCache.create(principal, options.cachename);
    if (cache == null) {
      throw new IOException("Unable to create the cache file " + options.cachename);
    }
    cache.update(credentials);
    cache.save();

    if (options.password == null) {
      // Assume we're running interactively
      debug(">>> Ticket stored in: File://" + options.cachename);
    } else {
      util.Arrays.fill(options.password, '0');
    }

    // clear the password
    if (psswd != null) {
      util.Arrays.fill(psswd, '0');
    }
    return credentials
  }

  private def setOptions(flag: Int, option: Int, opt: KDCOptions): Unit = {
    option match {
      case 0 =>
      case -1 => opt.set(flag, false)
      case 1 => opt.set(flag, true)
    }
  }

  def main(args: Array[String]): Unit = {
    kinit(args, "KerberosConsulLogin")
  }
}
