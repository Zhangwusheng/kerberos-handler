package com.bbles.kerberos.client

import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag
import javax.security.auth.login.{AppConfigurationEntry, Configuration}

import scala.collection.JavaConversions._
import scala.collection.mutable

class KerberosClientConfiguration(principal: String, keytab: String) extends Configuration {
  var useTicketCache: Boolean = false
  var isInitiator: Boolean = true
  if (keytab == null)
    useTicketCache = true

  override def getAppConfigurationEntry(name: String): Array[AppConfigurationEntry] =
  {
    val options: mutable.Map[String, String] = mutable.Map[String, String]()
    options.put("keyTab", keytab)
    options.put("principal", principal)
    options.put("useKeyTab", "true")
    options.put("storeKey", "true")
    options.put("doNotPrompt", "true")
    options.put("useTicketCache", "true")
    options.put("renewTGT", "true")
    options.put("refreshKrb5Config", "true")
    options.put("isInitiator", isInitiator.toString())
    val ticketCache = System.getenv("KRB5CCNAME")
    if (ticketCache != null)
      options.put("ticketCache", ticketCache)
    options.put("debug", "true")
    return Array[AppConfigurationEntry] {
      new AppConfigurationEntry(getKrb5LoginModuleName, LoginModuleControlFlag.REQUIRED, options)
    }
  }

  def getKrb5LoginModuleName: String = {
    if (System.getProperty("java.vendor").contains("IBM"))
      "com.ibm.security.auth.module.Krb5LoginModule"
    else
      "com.sun.security.auth.module.Krb5LoginModule"
  }
}
