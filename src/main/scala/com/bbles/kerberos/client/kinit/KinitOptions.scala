package com.bbles.kerberos.client.kinit

import com.bbles.kerberos.client.KerberosLogger
import com.bbles.kerberos.client.kinit.KinitOptions.KinitArgsParser
import com.bbles.kerberos.client.utils.TimeParser
import org.backuity.clist.{Cli, Command, opt}
import sun.security.krb5._
import sun.security.krb5.internal.KerberosTime
import sun.security.krb5.internal.ccache.FileCredentialsCache

/**
  * KinitOptions a class to parse args options
  *
  *
  * For all this options, please check RFC4120
  *
  * @param forwardable        : The ticket should be forwadable
  * @param proxiable          : The ticket should be proxiable
  * @param renew              : renewable ticket
  * @param lifetime           : The lifetime of the ticket
  * @param renewable_lifetime : The renewable lifetime of the credentials
  * @param target_service     : The service target for which we are loking for the ticket
  * @param keytab_file        : Keytab file name (the absolute path)
  * @param cachename          : The cache name (Full path)
  * @param principal          : The principal name used to proceed with the authentication
  * @param realm              : The realm (if not already specified by neither the principal nor the krb5.conf
  * @param password           : If the keytab will not used, the password should be provided for pre-auth
  * @param includeAddresses   : Include the host of the requester in the request
  */
@throws[RuntimeException]
@throws[RealmException]
class KinitOptions(
  var forwardable: Int = -1,
  var proxiable: Int = -1,
  var renewable: Int = -1,
  var renew: Boolean = false,
  var lifetime: KerberosTime = null,
  var renewable_lifetime: KerberosTime = null,
  var target_service: String = null,
  var keytab_file: String = null,
  var cachename: String = FileCredentialsCache.getDefaultCacheName,
  private var principal: PrincipalName = null,
  private var realm: String = null,
  var password: Array[Char] = null,
  var keytab: Boolean = false,
  private var includeAddresses: Boolean = true,
  private var useKeytab: Boolean = false
) extends KerberosLogger
{
  implicit def stringToPrincipalName(principal: String) = new PrincipalName(principal)

  /**
    * Convert string of format 'xxhyymzzs' => Now + xx hours + yy minutes + zz secondes (Kerberos time)
    *
    * @param time
    * @return
    */
  implicit def stringToKerberosTime(time: String) = TimeParser(time).toKerberosTime

  /**
    * Get the realm from the principal name if the option realm is not given
    *
    * @return the name of the realm
    */
  def getKDCRealm(): String = {
    if (realm.isEmpty)
      if (principal.getRealmString != null)
        return principal.getRealmString
    realm
  }

  /**
    * Check if the authenticated is keytab/cache/password based
    *
    * @return true (false) if the keytab name is (not) provided
    */
  def useKeytabFile = useKeytab

  /**
    * Parse the arguments
    *
    * @param args
    * @return An instance of KinitOptions
    */
  def this(args: KinitArgsParser) = this(
    forwardable = args.forwardable,
    proxiable = args.proxiable,
    renewable = args.renewable,
    renew = args.renew,
    lifetime = new KerberosTime(args.lifetime),
    renewable_lifetime = new KerberosTime(args.renewable_lifetime),
    target_service = args.target_service, password = args.password.toCharArray,
    keytab_file = args.keytab_file,
    cachename = args.cachename,
    principal = new PrincipalName(args.principal),
    realm = args.realm,
    includeAddresses = args.includeAddresses,
    useKeytab = !args.keytab_file.isEmpty
  )


  /**
    * Include the local address in the request
    *
    * @return
    */
  def getAddressOption = includeAddresses


  /**
    * Get the principal
    *
    * @return an instance of { @class PrincipalName}
    */
  def getPrincipal: PrincipalName = principal

}

object KinitOptions {
  def apply(args: Array[String]): KinitOptions = {
    val options = new KinitOptions()
    Cli.parse(args).withCommand(new KinitArgsParser) {
      case args => new KinitOptions(args)
    }.getOrElse(new KinitOptions)
  }

  /**
    * Generate an argument parsers for line commands
    */

  private class KinitArgsParser extends Command(name = "kinit", description = "Get Kerberos 5 credential ...") {
    var forwardable = opt[Int](default = -1, description = "Get forwardable ticket")
    var renewable = opt[Int](default = -1, description = "Get renewable ticket")
    var proxiable = opt[Int](default = -1, description = "Get proxiable ticket")
    var renew = opt[Boolean](abbrev = "renew", description = "Renew the current credential")
    var lifetime = opt[String](default = "19700101000000Z", description = "Validate the request")
    var renewable_lifetime = opt[String](name = "r", default = "19700101000000Z",
      description = "Renewable life time, the format should be (xxhyymzzs)")
    var target_service = opt[String](default = "",
      description = "The service the user is looking to get the ticket for")
    var keytab_file = opt[String](default = "", description = "the full path of the keytab")
    var cachename = opt[String](default = FileCredentialsCache.getDefaultCacheName,
      description = "Validate the request")
    var principal = opt[String](default = "", description = "the principal to be used for the authentication")
    var realm = opt[String](default = "", description = "realm")
    var password = opt[String](default = "", description = "Password if no keytab is specified")
    var debug = opt[Boolean](abbrev = "debug", description = "Make the program more verbose")
    var includeAddresses = opt[Boolean](abbrev = "include-address", description = "Validate the request",
      default = true)
  }

}