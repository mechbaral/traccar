/*
 * Copyright 2018 - 2019 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.traccar.protocol;

import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import org.traccar.BaseProtocol;
import org.traccar.PipelineBuilder;
import org.traccar.TrackerServer;
import org.traccar.config.Config;
import org.traccar.model.Command;

import java.nio.charset.StandardCharsets;

import jakarta.inject.Inject;

public class SegwayOmniProtocol extends BaseProtocol {

    @Inject
    public SegwayOmniProtocol(Config config) {

        setSupportedDataCommands(
                Command.TYPE_CUSTOM,
                Command.TYPE_POSITION_SINGLE,
                Command.TYPE_POSITION_PERIODIC,
                Command.TYPE_ALARM_ARM,
                Command.TYPE_ALARM_DISARM,
                Command.TYPE_ENGINE_STOP,
                Command.TYPE_ENGINE_RESUME);

        addServer(new TrackerServer(config, getName(), false) {
            @Override
            protected void addProtocolHandlers(PipelineBuilder pipeline, Config config) {

                pipeline.addLast(new LineBasedFrameDecoder(1024));

                /*
                 * Incoming packets are decoded into String.
                 * Outgoing commands are ByteBuf from SegwayOmniProtocolEncoder,
                 * so no StringEncoder is needed.
                 */
                pipeline.addLast(new StringDecoder(StandardCharsets.ISO_8859_1));

                pipeline.addLast(new SegwayOmniProtocolEncoder(SegwayOmniProtocol.this));
                pipeline.addLast(new SegwayOmniProtocolDecoder(SegwayOmniProtocol.this));
            }
        });
    }

}