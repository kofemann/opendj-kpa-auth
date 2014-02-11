/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at
 * trunk/opends/resource/legal-notices/OpenDS.LICENSE
 * or https://OpenDS.dev.java.net/OpenDS.LICENSE.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at
 * trunk/opends/resource/legal-notices/OpenDS.LICENSE.  If applicable,
 * add the following below this CDDL HEADER, with the fields enclosed
 * by brackets "[]" replaced with your own identifying information:
 *      Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 *
 *      Copyright 2013 Plausible Labs Cooperative, Inc.
 *      Copyright 2011 ForgeRock AS.
 */

package coop.plausible.opendj.plugin.kpa;

import com.sun.security.auth.module.Krb5LoginModule;
import org.opends.messages.Message;
import org.opends.server.api.AuthenticationPolicy;
import org.opends.server.api.AuthenticationPolicyState;
import org.opends.server.loggers.debug.DebugTracer;
import org.opends.server.types.*;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import java.io.IOException;
import java.util.*;


import static org.opends.server.loggers.ErrorLogger.logError;

import static org.opends.server.loggers.debug.DebugLogger.debugEnabled;
import static org.opends.server.loggers.debug.DebugLogger.getTracer;

/**
 * Kerberos authentication policy state.
 */
class KerberosPolicyState extends AuthenticationPolicyState {
    /** The parent kerberos policy. */
    private final KerberosPolicy policy;

    private final DebugTracer TRACER = getTracer();

    /**
     * Create a new policy state instance.
     *
     * @param policy The parent kerberos policy.
     * @param userEntry The user entry to be managed.
     */
    public KerberosPolicyState (KerberosPolicy policy, Entry userEntry) {
        super(userEntry);
        this.policy = policy;
    }

    @Override
    public AuthenticationPolicy getAuthenticationPolicy () {
        return policy;
    }

    @Override
    public boolean passwordMatches (final ByteString byteString) throws DirectoryException {
        /**
         * It's not possible to authenticate an arbitrary principal if this system property
         * is set, as it will override the principal we provide below.
         */
        if (System.getProperty("sun.security.krb5.principal") != null) {
            logError(Message.fromObject("The 'sun.security.krb5.principal' system property is set. This will override all " +
                "the authentication principal when performing Kerberos pass-through authentication."));
            return false;
        }

        /* Find the first available user attribute */
        String userPrincipal = null;
        for (AttributeType at : this.policy.getConfig().getMappedAttribute()) {
            final List<Attribute> attributes = userEntry.getAttribute(at);
            if (attributes == null || attributes.isEmpty())
                continue;

            for (Attribute attr : attributes) {
                if (attr.isEmpty())
                    continue;

                userPrincipal = attr.iterator().next().getValue().toString();
                break;
            }

            if (userPrincipal != null)
                break;
        }

        if (userPrincipal == null) {
            throw new DirectoryException(ResultCode.INVALID_CREDENTIALS,
                    Message.fromObject("The user \"%s\" could not be authenticated using Kerberos PTA policy \"%s\" because the following mapping attributes were not found in the user's entry: %s",
                        String.valueOf(userEntry.getDN()),
                        String.valueOf(this.policy.getConfig().dn()),
                        mappedAttributesAsString(this.policy.getConfig().getMappedAttribute())));
        }

	String krb5Principal = userPrincipal + "@" + this.policy.getConfig().getKrb5Realm();
        /* Kerberos module options */
        final Map<String,Object> options = new HashMap<String, Object>();
        options.put("refreshKrb5Config", "true"); // Fetch most up-to-date configuration
        options.put("useTicketCache", "true"); // Do not reference the hosts' ticket cache
        options.put("doNotPrompt", "true"); // Fetch principal et al from the shared state
        options.put("useFirstPass", "true"); // Use auth info from the shared state, do not retry

        /* Kerberos module state */
        final Map<String,Object> state = new HashMap<String, Object>();
        state.put("javax.security.auth.login.name", krb5Principal);
        state.put("javax.security.auth.login.password", byteString.toString().toCharArray());

        /* Create the noop handler */
        CallbackHandler cbh = new CallbackHandler() {
            @Override
            public void handle (Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                for (Callback callback : callbacks) {
                    throw new UnsupportedCallbackException(callback, "Unrecognized Callback " + callback);
                }
            }
        };

        /* Instantiate the login context */
        final Krb5LoginModule loginModule = new Krb5LoginModule();
        loginModule.initialize(new Subject(), cbh, state, options);
        try {
            loginModule.login();
            loginModule.logout();
        } catch (FailedLoginException e) {
            if (debugEnabled()) {
                TRACER.debugCaught(DebugLogLevel.INFO, e);
            }
            return false;
        } catch (LoginException e) {
            logError(Message.fromObject("Failed to issue Kerberos login request: " + e.getMessage()));
            if (debugEnabled()) {
                TRACER.debugCaught(DebugLogLevel.ERROR, e);
            }

            return false;
        }

        return true;
    }

    // This was copied from ForgeRock's LDAPPassThroughAuthenticationPolicyFactory
    private static String mappedAttributesAsString (final Collection<AttributeType> attributes) {
        switch (attributes.size()) {
            case 0:
                return "";
            case 1:
                return attributes.iterator().next().getNameOrOID();
            default:
                final StringBuilder builder = new StringBuilder();
                final Iterator<AttributeType> i = attributes.iterator();
                builder.append(i.next().getNameOrOID());
                while (i.hasNext())
                {
                    builder.append(", ");
                    builder.append(i.next().getNameOrOID());
                }
                return builder.toString();
        }
    }
}
