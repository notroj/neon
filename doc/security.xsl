<?xml version="1.0"?>
<!--
   Generate SECURITY.md (GitHub-Flavoured Markdown) from the "HTTP
   Client Security" section of the neon manual.  Intended to be run
   against doc/manual.xml (not doc/security.xml directly), so that
   the manual's entities and cross-references resolve correctly;
   only the sect1 with id="security" is selected for output.

   Hand-written rather than derived from the DocBook XSL
   stylesheets (unlike doc/html.xsl and doc/man.xsl), since no
   Markdown backend exists there.  Only covers the subset of
   DocBook markup actually used in doc/security.xml.
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0">

<xsl:output method="text" encoding="UTF-8"/>
<xsl:strip-space elements="*"/>

<xsl:template match="/"><xsl:text># </xsl:text><xsl:value-of select="id('security')/title"/><xsl:text>

&gt; Generated from `doc/security.xml`; do not edit directly.

</xsl:text><xsl:apply-templates select="id('security')/*[not(self::title)]"/></xsl:template>

<xsl:template match="sect2"><xsl:text>## </xsl:text><xsl:value-of select="title"/><xsl:text>&#10;&#10;</xsl:text><xsl:apply-templates select="*[not(self::title)]"/></xsl:template>

<xsl:template match="para"><xsl:apply-templates/><xsl:text>&#10;&#10;</xsl:text></xsl:template>

<xsl:template match="itemizedlist"><xsl:apply-templates select="listitem" mode="bullet"/></xsl:template>

<!-- listitem's content is always a single para, which already
     supplies the trailing blank line between items -->
<xsl:template match="listitem" mode="bullet"><xsl:text>- </xsl:text><xsl:apply-templates/></xsl:template>

<xsl:template match="orderedlist"><xsl:apply-templates select="listitem" mode="number"/></xsl:template>

<xsl:template match="listitem" mode="number"><xsl:number/><xsl:text>. </xsl:text><xsl:apply-templates/></xsl:template>

<xsl:template match="literal|parameter|sgmltag"><xsl:text>`</xsl:text><xsl:apply-templates/><xsl:text>`</xsl:text></xsl:template>

<xsl:template match="emphasis"><xsl:text>*</xsl:text><xsl:apply-templates/><xsl:text>*</xsl:text></xsl:template>

<xsl:template match="ulink"><xsl:text>[</xsl:text><xsl:apply-templates/><xsl:text>](</xsl:text><xsl:value-of select="@url"/><xsl:text>)</xsl:text></xsl:template>

<!-- render as inline code with a trailing "()"; every xref target
     in doc/security.xml is a refentry for a C function -->
<xsl:template match="xref"><xsl:text>`</xsl:text><xsl:value-of select="id(@linkend)"/><xsl:text>()`</xsl:text></xsl:template>

<!-- collapse whitespace runs (from source line-wrapping) to a
     single space, without trimming a leading/trailing space that
     separates this text from adjacent inline markup -->
<xsl:template match="text()"><xsl:call-template name="collapse-ws"><xsl:with-param name="s" select="translate(., '&#9;&#10;&#13;', '   ')"/></xsl:call-template></xsl:template>

<xsl:template name="collapse-ws">
<xsl:param name="s"/>
<xsl:choose>
<xsl:when test="contains($s, '  ')"><xsl:call-template name="collapse-ws"><xsl:with-param name="s" select="concat(substring-before($s, '  '), ' ', substring-after($s, '  '))"/></xsl:call-template></xsl:when>
<xsl:otherwise><xsl:value-of select="$s"/></xsl:otherwise>
</xsl:choose>
</xsl:template>

</xsl:stylesheet>
