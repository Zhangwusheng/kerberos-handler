package com.bbles.kerberos.client.kparser

import sun.security.krb5.Credentials
import sun.security.krb5.internal.ccache.CredentialsCache
import sun.security.krb5.internal.crypto.EType

/**
  * KParser : A simple scala application to parser kerberos cache
  * for investigation.
  *
  * command : com.bbles.kerberos.client.KParser --cachename FULL_PATH (by default /tmp/krbcc_${uid})
  */
object KParser {

  /**
    * Generate a pretty string to display the content of a kerberos cache.
    *
    * @param credential : The credential cache to be displayed
    * @return string , formatted credential
    */
  private[this] def formatCache(credential: Credentials): String = {
    s"\n----Credentials----" +
      s"\n\t  Client:                 ${credential.getClient}" +
      s"\n\t  Server:                 ${credential.getServer}" +
      s"\n\t  Ticket Encyption Type:  ${EType.toString(credential.getTicket.encPart.getEType)}" +
      s"\n\t  startTime:              ${
        if (credential.getStartTime != null) credential.getStartTime else "null"
      }" +
      s"\n\t  endTime:                ${credential.getEndTime}" +
      s"\n\t  authTime:               ${credential.getAuthTime}" +
      s"\n\t  Flags:                  ${credential.getTicketFlags}" +
      "\n----Credentials end----"
  }


  private[this] def parser(args: Array[String]): Unit = {
    val options = KParserOptions(args)


    // Set the cache name to look for
    val cacheName = if (options.cachename.isEmpty)
      CredentialsCache.cacheName()
    else
      options.cachename

    // Parse the cache and display the output
    CredentialsCache
      .getInstance(cacheName)
      .getCredsList
      .map(_.setKrbCreds)
      .foreach(c => print(formatCache(c)))

  }

  def main(args: Array[String]): Unit = {
    parser(args)
  }
}
