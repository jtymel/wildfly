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

package org.jboss.as.clustering.jgroups.subsystem;

import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

import org.jboss.as.clustering.controller.AttributeMarshallers;
import org.jboss.as.clustering.controller.AttributeParsers;
import org.jboss.as.clustering.controller.ChildResourceDefinition;
import org.jboss.as.clustering.controller.Operations;
import org.jboss.as.clustering.controller.ResourceDescriptor;
import org.jboss.as.clustering.controller.ResourceServiceBuilderFactory;
import org.jboss.as.clustering.controller.ResourceServiceHandler;
import org.jboss.as.clustering.controller.RestartParentResourceRegistration;
import org.jboss.as.clustering.controller.SimpleResourceServiceHandler;
import org.jboss.as.clustering.controller.transform.LegacyPropertyMapGetOperationTransformer;
import org.jboss.as.clustering.controller.transform.LegacyPropertyWriteOperationTransformer;
import org.jboss.as.clustering.controller.transform.SimpleOperationTransformer;
import org.jboss.as.clustering.controller.validation.ModuleIdentifierValidatorBuilder;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ModelVersion;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleMapAttributeDefinition;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.as.controller.operations.global.MapOperations;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.transform.TransformationContext;
import org.jboss.as.controller.transform.description.AttributeConverter;
import org.jboss.as.controller.transform.description.DiscardAttributeChecker;
import org.jboss.as.controller.transform.description.RejectAttributeChecker;
import org.jboss.as.controller.transform.description.ResourceTransformationDescriptionBuilder;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jgroups.stack.Protocol;
import org.wildfly.clustering.jgroups.spi.ChannelFactory;
import org.wildfly.clustering.jgroups.spi.ProtocolConfiguration;

/**
 * Resource description for /subsystem=jgroups/stack=X/protocol=Y
 *
 * @author Richard Achmatowicz (c) 2011 Red Hat Inc.
 * @author Paul Ferraro
 */
public class AbstractProtocolResourceDefinition<P extends Protocol, C extends ProtocolConfiguration<P>> extends ChildResourceDefinition<ManagementResourceRegistration> {

    enum Attribute implements org.jboss.as.clustering.controller.Attribute {
        MODULE(ModelDescriptionConstants.MODULE, ModelType.STRING, builder -> builder
                .setDefaultValue(new ModelNode("org.jgroups"))
                .setValidator(new ModuleIdentifierValidatorBuilder().configure(builder).build())),
        PROPERTIES(ModelDescriptionConstants.PROPERTIES),
        STATISTICS_ENABLED(ModelDescriptionConstants.STATISTICS_ENABLED, ModelType.BOOLEAN),
        ;
        private final AttributeDefinition definition;

        Attribute(String name, ModelType type) {
            this(name, type, UnaryOperator.identity());
        }

        Attribute(String name, ModelType type, UnaryOperator<SimpleAttributeDefinitionBuilder> configurator) {
            this.definition = configurator.apply(new SimpleAttributeDefinitionBuilder(name, type)
                    .setAllowExpression(true)
                    .setRequired(false)
                    .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                    ).build();
        }

        Attribute(String name) {
            this.definition = new SimpleMapAttributeDefinition.Builder(name, true)
                    .setAllowExpression(true)
                    .setAttributeMarshaller(AttributeMarshallers.PROPERTY_LIST)
                    .setAttributeParser(AttributeParsers.COLLECTION)
                    .setDefaultValue(new ModelNode().setEmptyObject())
                    .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                    .build();
        }

        @Override
        public AttributeDefinition getDefinition() {
            return this.definition;
        }
    }

    @Deprecated
    enum DeprecatedAttribute implements org.jboss.as.clustering.controller.Attribute {
        TYPE(ModelDescriptionConstants.TYPE, ModelType.STRING, JGroupsModel.VERSION_3_0_0),
        ;
        private final AttributeDefinition definition;

        DeprecatedAttribute(String name, ModelType type, JGroupsModel deprecation) {
            this.definition = new SimpleAttributeDefinitionBuilder(name, type)
                    .setAllowExpression(true)
                    .setRequired(false)
                    .setDeprecated(deprecation.getVersion())
                    .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                    .build();
        }

        @Override
        public AttributeDefinition getDefinition() {
            return this.definition;
        }
    }

    /**
     * Builds transformations common to both stack protocols and transport.
     */
    @SuppressWarnings("deprecation")
    static void addTransformations(ModelVersion version, ResourceTransformationDescriptionBuilder builder) {

        if (JGroupsModel.VERSION_4_1_0.requiresTransformation(version)) {
            builder.getAttributeBuilder()
                    .setDiscard(DiscardAttributeChecker.UNDEFINED, Attribute.STATISTICS_ENABLED.getDefinition())
                    .addRejectCheck(RejectAttributeChecker.DEFINED, Attribute.STATISTICS_ENABLED.getDefinition())
                    .end();
        }

        if (JGroupsModel.VERSION_3_0_0.requiresTransformation(version)) {
            AttributeConverter typeConverter = new AttributeConverter.DefaultAttributeConverter() {
                @Override
                protected void convertAttribute(PathAddress address, String name, ModelNode value, TransformationContext context) {
                    if (!value.isDefined()) {
                        value.set(address.getLastElement().getValue());
                    }
                }
            };
            builder.getAttributeBuilder()
                    .setDiscard(new DiscardAttributeChecker.DiscardAttributeValueChecker(Attribute.MODULE.getDefinition().getDefaultValue()), Attribute.MODULE.getDefinition())
                    .addRejectCheck(RejectAttributeChecker.DEFINED, Attribute.MODULE.getDefinition())
                    .setValueConverter(typeConverter, DeprecatedAttribute.TYPE.getDefinition())
                    .end();

            builder.addRawOperationTransformationOverride(MapOperations.MAP_GET_DEFINITION.getName(), new SimpleOperationTransformer(new LegacyPropertyMapGetOperationTransformer()));

            for (String opName : Operations.getAllWriteAttributeOperationNames()) {
                builder.addOperationTransformationOverride(opName)
                        .inheritResourceAttributeDefinitions()
                        .setCustomOperationTransformer(new LegacyPropertyWriteOperationTransformer());
            }
        }

        PropertyResourceDefinition.buildTransformation(version, builder);
    }

    static class LegacyAddOperationTransformation implements UnaryOperator<OperationStepHandler> {
        private final Predicate<ModelNode> legacy;

        LegacyAddOperationTransformation(Predicate<ModelNode> legacy) {
            this.legacy = legacy;
        }

        @Override
        public OperationStepHandler apply(OperationStepHandler handler) {
            return (context, operation) -> {
                if (this.legacy.test(operation)) {
                    PathElement path = context.getCurrentAddress().getLastElement();
                    String key = path.getKey();
                    // This is a legacy add operation - process it using the generic handler
                    Operations.setPathAddress(operation, context.getCurrentAddress().getParent().append(PathElement.pathElement(key, String.join(".", org.jgroups.conf.ProtocolConfiguration.protocol_prefix, path.getValue()))));
                    OperationStepHandler genericHandler = context.getResourceRegistration().getParent().getOperationHandler(PathAddress.pathAddress(PathElement.pathElement(key)), ModelDescriptionConstants.ADD);
                    // Process this step first to preserve protocol order
                    context.addStep(operation, genericHandler, OperationContext.Stage.MODEL, true);
                } else {
                    handler.execute(context, operation);
                }
            };
        }
    }

    private final Consumer<ResourceDescriptor> descriptorConfigurator;
    private final ResourceServiceHandler handler;
    private final ResourceServiceBuilderFactory<ChannelFactory> parentBuilderFactory;
    private final BiConsumer<ManagementResourceRegistration, ManagementResourceRegistration> registrationConfigurator;

    @SuppressWarnings("deprecation")
    AbstractProtocolResourceDefinition(Parameters parameters, Consumer<ResourceDescriptor> descriptorConfigurator, ResourceServiceBuilderFactory<C> builderFactory, ResourceServiceBuilderFactory<ChannelFactory> parentBuilderFactory, BiConsumer<ManagementResourceRegistration, ManagementResourceRegistration> registrationConfigurator) {
        super(parameters);
        this.descriptorConfigurator = descriptorConfigurator.andThen(descriptor -> descriptor.addAttributes(Attribute.class).addExtraParameters(DeprecatedAttribute.class));
        this.handler = new SimpleResourceServiceHandler<>(builderFactory);
        this.parentBuilderFactory = parentBuilderFactory;
        this.registrationConfigurator = registrationConfigurator.andThen((parent, registration) -> {
            if (registration.getPathAddress().getLastElement().isWildcard()) {
                new PropertyResourceDefinition().register(registration);
            }
        });
    }

    @Override
    public void register(ManagementResourceRegistration parent) {
        ManagementResourceRegistration registration = parent.registerSubModel(this);

        ResourceDescriptor descriptor = new ResourceDescriptor(this.getResourceDescriptionResolver());
        this.descriptorConfigurator.accept(descriptor);
        new RestartParentResourceRegistration<>(this.parentBuilderFactory, descriptor, this.handler).register(registration);

        this.registrationConfigurator.accept(parent, registration);
    }
}
