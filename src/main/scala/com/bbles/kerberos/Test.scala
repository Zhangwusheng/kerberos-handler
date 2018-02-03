package com.bbles.kerberos

import com.bbles.kerberos.client.KerberosLogger
import sun.security.krb5.internal.ccache.CredentialsCache
import sun.security.krb5.{Credentials, KrbTgsReq, PrincipalName}

object Test extends KerberosLogger {
  def main(argvs: Array[String]): Unit = {
    val krb =
      new KrbTgsReq(
        Credentials.acquireDefaultCreds(),
        new PrincipalName("")
      )
    // Send request
    var cre = krb.sendAndGetCreds
    print(cre.getTicket.tkt_vno)
    var cc = cre.getCache
    cc.save()
    var l = CredentialsCache.getInstance()
    for (crd <- l.getCredsList)
      Credentials.printDebug(crd.setKrbCreds)
  }
}