package com.bbles.kerberos.client.kinit

import com.bbles.kerberos.client.KerberosLogger
import org.backuity.clist.{Cli, Command, opt}
import sun.security.krb5._
import sun.security.krb5.internal.KerberosTime
import sun.security.krb5.internal.ccache.FileCredentialsCache

@throws[RuntimeException]
@throws[RealmException]
class KinitOptions(
  var forwardable: Int = -1,
  var proxiable: Int = -1,
  var renew: Boolean = false,
  var lifetime: KerberosTime = null,
  var renewable_lifetime: KerberosTime = null,
  var target_service: String = null,
  var keytab_file: String = null,
  var cachename: String = FileCredentialsCache.getDefaultCacheName,
  private var principal: PrincipalName = null,
  private[this] var realm: String = null,
  var password: Array[Char] = null,
  var keytab: Boolean = false,
  private var includeAddresses: Boolean = true,
  private var useKeytab: Boolean = false,
  private var ktabName: String = null
) extends KerberosLogger
{
  implicit def stringToPrincipalName(principal: String) = new PrincipalName(principal)

  implicit def stringToKerberosTime(time: String) = new KerberosTime("19700101000000Z")

  def getKDCRealm(): String = {
    if (realm == null)
      if (principal != null)
        return principal.getRealmString
    realm
  }

  def setCacheName(_ccname: String): Unit = {
    cachename = _ccname
  }

  def useKeytabFile = useKeytab

  def this(args: KinitArgsParser) = this(
    forwardable = args.forwardable,
    proxiable = args.proxiable,
    renew = args.renew,
    lifetime = args.lifetime,
    renewable_lifetime = args.renewable_lifetime,
    target_service = args.target_service, password = args.password.toCharArray,
    keytab_file = args.keytab_file,
    cachename = args.cachename,
    principal = args.principal,
    realm = args.realm,
    includeAddresses = args.includeAddresses,
    useKeytab = !args.keytab_file.isEmpty,
    ktabName = args.keytab_file
  )

  def getAddressOption = includeAddresses

  def getPrincipal: PrincipalName = principal

}

object KinitOptions {
  def apply(args: Array[String]): KinitOptions = {
    val options = new KinitOptions()
    Cli.parse(args).withCommand(new KinitArgsParser) {
      case args => new KinitOptions(args)
    }.getOrElse(new KinitOptions())
  }

  /**
    * Generate an argument parsers for line commands
    */

  private class KinitArgsParser extends Command(name = "kinit", description = "Get Kerberos 5 credential ...") {
    var forwardable = opt[Int](default = -1, description = "Get forwardable ticket to different host")
    var renewable = opt[Int](default = -1, description = "Get renewable ticket")
    var proxiable = opt[Int](default = -1, description = "Get proxiable ticket")
    var renew = opt[Boolean](abbrev = "renew", description = "Renew the current credential")
    var lifetime = opt[String](default = "19700101000000Z", description = "Validate the request")
    var renewable_lifetime = opt[String](name = "r", default = "19700101000000Z",
      description = "Validate the request")
    var target_service = opt[String](default = "", description = "Validate the request")
    var keytab_file = opt[String](default = "", description = "Validate the request")
    var cachename = opt[String](default = "", description = "Validate the request")
    var principal = opt[String]( default = "", description = "Validate the request")
    var realm = opt[String](default = "", description = "Validate the request")
    var password = opt[String](default = "", description = "Validate the request")
    var keytab = opt[Boolean](abbrev = "keytab", description = "Validate the request")
    var debug = opt[Boolean](abbrev = "debug", description = "Validate the request")
    var includeAddresses = opt[Boolean](abbrev = "include-address", description = "Validate the request",
      default = true)
  }

}