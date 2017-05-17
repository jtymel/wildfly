/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.test.integration.elytron.jacc;

import java.io.File;

//import static org.junit.Assert.assertFalse;
//import static org.junit.Assert.assertTrue;
import java.io.InputStream;
import java.net.URL;

import org.dom4j.Document;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.test.categories.CommonCriteria;
import org.jboss.as.test.integration.management.util.CLIWrapper;
//import org.jboss.as.test.integration.security.common.SecurityTraceLoggingServerSetupTask;
import org.jboss.as.test.shared.ServerReload;
import org.jboss.logging.Logger;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;

/**
 * Test based on a section 3.1.3 "Translating Servlet Deployment Descriptors" of the JACC 1.1 specification. This tests works
 * with deployment descriptor (web.xml) content which is a part of the JACC specification as an Example section 3.1.3.4.
 *
 * @author Josef Cacek
 */
@RunWith(Arquillian.class)
@ServerSetup({/*SecurityTraceLoggingServerSetupTask.class, */JACCTranslateServletDDTestCase.JaccSetupTask.class})
@RunAsClient
@Category(CommonCriteria.class)
public class JACCTranslateServletDDTestCase {

    private static final String SECURITY_DOMAIN_NAME = "jacc-test";
    private static final String WEBAPP_NAME = "jacc-test.war";
    private static final Logger LOGGER = Logger.getLogger(JACCTranslateServletDDTestCase.class);

    // Public methods --------------------------------------------------------
    /**
     * Creates {@link WebArchive}.
     *
     * @return
     */
    @Deployment
    public static WebArchive warDeployment() {
        final WebArchive war = ShrinkWrap.create(WebArchive.class, WEBAPP_NAME);
        war.addClass(ListJACCPoliciesServlet.class);
        war.addAsWebInfResource(JACCTranslateServletDDTestCase.class.getPackage(), "SMAZAT-web-JACC11-example.xml", "web.xml");
        war.addAsWebInfResource(new StringAsset("<jboss-web>" + //
                "<security-domain>" + SECURITY_DOMAIN_NAME + "</security-domain>" + //
                "</jboss-web>"), "jboss-web.xml");

        war.as(ZipExporter.class).exportTo(new File("/home/jtymel/trash/exportedWars/JACCTranslateServletDDTestCase.war"), true);
        return war;
    }

    /**
     * Test canonical form of HTTP Method list.
     *
     * @see #testHTTPMethodExceptionList(URL) for some other tests
     */
    @Test
    public void testHTTPMethodCanonical(@ArquillianResource URL webAppURL) throws Exception {
        final Node node = getContextPolicyNode(webAppURL, WEBAPP_NAME);
        System.out.println("####### ####### ###### " + node.asXML());
//        assertTrue("HTTP Method names should be sorted alphabetically", node.selectNodes("*/Permission[@actions='PUT,DELETE']")
//                .isEmpty());
//        assertFalse("HTTP Method names should be sorted alphabetically", node
//                .selectNodes("*/Permission[@actions='DELETE,PUT']").isEmpty());
//
//        assertFalse("HTTP Method names should be sorted alphabetically",
//                node.selectNodes("RolePermissions/Role/Permission[@actions='GET,POST']").isEmpty());
//        assertTrue("HTTP Method names should be sorted alphabetically",
//                node.selectNodes("RolePermissions/Role/Permission[@actions='POST,GET']").isEmpty());
//        assertFalse("HTTP Method names should be sorted alphabetically, followed by colon-separated transport guarantee", node
//                .selectNodes("UncheckedPermissions/Permission[@actions='GET,POST:CONFIDENTIAL']").isEmpty());
    }

    // Private methods -------------------------------------------------------
    /**
     * Retruns Node representing ContextPolicy with given contextId.
     *
     * @param webAppURL
     */
    private Node getContextPolicyNode(final URL webAppURL, String contextId) throws Exception {
        final URL servletURL = new URL(webAppURL.toExternalForm() + ListJACCPoliciesServlet.SERVLET_PATH.substring(1));
        System.out.println("%%%%%% %%%%%% " + servletURL);

        LOGGER.trace("Testing JACC permissions: " + servletURL);

        try (InputStream is = servletURL.openStream()) {
            final Document document = new SAXReader().read(is);
            System.out.println("$$$$$$$$$$$$ $$$$$$$$$$$ " + document.asXML());

            final String xpathBase = "/" + ListJACCPoliciesServlet.ROOT_ELEMENT
                    + "/ActiveContextPolicies/ContextPolicy[@contextID='" + contextId + "']";
            final Node contextPolicyNode = document.selectSingleNode(xpathBase);
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace(contextPolicyNode.asXML());
            }
            return contextPolicyNode;
        }
    }

    // Embedded classes ------------------------------------------------------
    static class JaccSetupTask implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String string) throws Exception {
            try (CLIWrapper cli = new CLIWrapper(true)) {
                // set according to https://docs.jboss.org/author/display/WFLY/Elytron+and+Java+Authorization+Contract+for+Containers+%28JACC%29
                cli.sendLine("/subsystem=security:write-attribute(name=initialize-jacc,value=false)");
                cli.sendLine("/subsystem=elytron/policy=jacc:add(jacc-policy=[{name=jacc}])");
                cli.sendLine(String.format(
                        "/subsystem=undertow/application-security-domain=%s:add(http-authentication-factory=application-http-authentication,enable-jacc)",
                        SECURITY_DOMAIN_NAME));
            }

            ServerReload.reloadIfRequired(managementClient.getControllerClient());
        }

        @Override
        public void tearDown(ManagementClient managementClient, String string) throws Exception {
            try (CLIWrapper cli = new CLIWrapper(true)) {
                cli.sendLine("/subsystem=security:write-attribute(name=initialize-jacc,value=true)");
                cli.sendLine("/subsystem=elytron/policy=jacc:remove()");
                cli.sendLine(String.format(
                        "/subsystem=undertow/application-security-domain=%s:remove()",
                        SECURITY_DOMAIN_NAME));
            }
            ServerReload.reloadIfRequired(managementClient.getControllerClient());
        }

    }
}
