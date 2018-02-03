package com.bbles.kerberos.client.kparser

import com.bbles.kerberos.client.KerberosLogger
import com.bbles.kerberos.client.kparser.KParserOptions.KParserArgsParser
import org.backuity.clist.{Cli, Command, opt}
import sun.security.krb5._
import sun.security.krb5.internal.ccache.FileCredentialsCache

/**
  * KParserOptions a class to parse args options
  *
  *
  * For all this options, please check RFC4120
  *
  * @param cachename : The cache name (Full path)(/tmp/krbcc_{user_id} by default)
  */
@throws[RuntimeException]
@throws[RealmException]
class KParserOptions(var cachename: String = null) extends KerberosLogger
{
  /**
    * Parse the arguments
    *
    * @param args
    * @return An instance of KinitOptions
    */
  def this(args: KParserArgsParser) = this(args.cachename)
}

object KParserOptions {
  def apply(args: Array[String]): KParserOptions = {
    Cli.parse(args).withCommand(new KParserArgsParser) {
      case args => new KParserOptions(args)
    }.getOrElse(new KParserOptions)
  }

  /**
    * Generate an argument parsers for line commands
    */

  private class KParserArgsParser extends Command(name = "kparser", description = "Parse Credential Cache") {
    var cachename = opt[String](default = FileCredentialsCache.getDefaultCacheName,
      description = "Cache name to be parsed")
  }

}