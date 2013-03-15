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
 *      Copyright 2006-2008 Sun Microsystems, Inc.
 */
package coop.plausible.opendj.plugin.kpa;

import coop.plausible.opendj.plugin.kpa.server.KerberosPassThroughAuthenticationPolicyCfg;
import org.opends.messages.Message;
import org.opends.server.api.AuthenticationPolicy;
import org.opends.server.api.AuthenticationPolicyFactory;
import org.opends.server.config.ConfigException;
import org.opends.server.types.InitializationException;

import java.util.List;

/**
 * Kerberos pass-through authentication policy factory.
 */
public class KerberosPolicyFactory implements AuthenticationPolicyFactory<KerberosPassThroughAuthenticationPolicyCfg> {
    /**
     * Default constructor used by the admin framework when instantiating
     * the plugin.
     */
    public KerberosPolicyFactory () {
        super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthenticationPolicy createAuthenticationPolicy (KerberosPassThroughAuthenticationPolicyCfg config) throws ConfigException, InitializationException {
        return new KerberosPolicy(config);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isConfigurationAcceptable (KerberosPassThroughAuthenticationPolicyCfg kerberosPluginCfg, List<Message> messages) {
        return true;
    }
}
