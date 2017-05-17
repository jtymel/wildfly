/*
 * JBoss, Home of Professional Open Source.
 * Copyright (c) 2011, Red Hat, Inc., and individual contributors
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

import java.io.IOException;
import java.io.PrintWriter;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
//import java.security.CodeSource;
//import java.security.Permission;
//import java.security.PermissionCollection;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
//import java.util.Collections;
//import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//import org.jboss.security.jacc.DelegatingPolicy;
//import org.wildfly.security.authz.jacc.ElytronPolicyConfigurationFactory;
import org.wildfly.security.authz.jacc.JaccDelegatingPolicy;

/**
 * A simple servlet that lists JACC policies.
 *
 * @author Josef Cacek
 */
@WebServlet(urlPatterns = {ListJACCPoliciesServlet.SERVLET_PATH})
public class ListJACCPoliciesServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public static final String ROOT_ELEMENT = "jacc-policies";
    public static final String SERVLET_PATH = "/listJACCPolicies";

    /**
     * Writes simple text response.
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/plain");
        final PrintWriter writer = resp.getWriter();
        writer.append("<" + ROOT_ELEMENT + ">\n");
        Policy.setPolicy(new JaccDelegatingPolicy());
        Policy policy = Policy.getPolicy();

        try {
            Subject subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
            writer.append("####### ##### ##### ### " + subject + " \n");

            if (policy instanceof JaccDelegatingPolicy) {
                PermissionCollection perms = ((JaccDelegatingPolicy) policy).getPermissions(new ProtectionDomain(
                        new CodeSource(null, (Certificate[]) null),
                        null, null,
                        subject.getPrincipals().toArray(new Principal[subject.getPrincipals().size()])
                ));
                writer.append("####### ##### ##### ### " + perms.elements().hasMoreElements() + " \n");

                for (Permission permission : Collections.list(perms.elements())) {
                    writer.append("####### ##### ##### ### role: " + permission + " \n");
                }
            }
        } catch (PolicyContextException ex) {
            Logger.getLogger(ListJACCPoliciesServlet.class.getName()).log(Level.SEVERE, null, ex);
        }

        try {
            HttpServletRequest requestFromPolicy = (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");

            if (requestFromPolicy != null) {
                writer.append("Obtained request from context.\n");
                writer.append(requestFromPolicy + "\n");
                writer.append(requestFromPolicy.getQueryString() + "\n");

                if ("true".equals(requestFromPolicy.getAttribute("jaccTest"))) {
                    writer.append("Attribute present in request from context.");
                }

                if ("true".equals(requestFromPolicy.getParameter("jacc_test"))) {
                    writer.append("Request parameter present in request from context.");
                }

            }
        } catch (PolicyContextException ex) {
        }

        System.out.println("####### ######## " + policy);
        System.out.println("####### ######## " + policy.getType());
        System.out.println("####### ######## " + policy.getProvider());
//        if (policy instanceof JaccDelegatingPolicy) {
//            ((JaccDelegatingPolicy) policy).getPermissions( new ProtectionDomain(
//                new CodeSource(null, (Certificate[]) null),
//                null, null,
//                subject.getPrincipals().toArray(new Principal[subject.getPrincipals().size()])
//            ));
//        }
//            PermissionCollection perms =  ((JaccDelegatingPolicy) policy).implies(null, null); // not supported, ma se pouzit implies
//            List<Permission> permissions = Collections.list(perms.elements());
//            System.out.println("######## ########## " + permissions.size());
//            for (Permission permission : permissions) {
//                System.out.println("########### ######## " + permission);
//            }
////            writer.append(((DelegatingPolicy) policy).listContextPolicies() //
////                    //workarounds for https://issues.jboss.org/browse/SECURITY-663
////                    .replaceAll("Permission name=", "Permission' name=") //
////                    .replaceAll("RolePermssions", "RolePermissions")) //
////            ;
//        }
        writer.append("</" + ROOT_ELEMENT + ">\n");
        writer.close();
    }
}
