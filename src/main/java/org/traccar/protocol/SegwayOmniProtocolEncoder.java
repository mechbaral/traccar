/*
 * Copyright 2018 - 2019 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.traccar.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.traccar.BaseProtocolEncoder;
import org.traccar.Protocol;
import org.traccar.model.Command;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class SegwayOmniProtocolEncoder extends BaseProtocolEncoder {

    private static final String USER_ID = "1234";
    private static final int KEY_VALID_SECONDS = 20;

    public SegwayOmniProtocolEncoder(Protocol protocol) {
        super(protocol);
    }

    private SegwayOmniProtocolDecoder getDecoder(Channel channel) {
        if (channel != null) {
            return channel.pipeline().get(SegwayOmniProtocolDecoder.class);
        }
        return null;
    }

    private String getServerHeader(Channel channel) {

        SegwayOmniProtocolDecoder decoder = getDecoder(channel);

        if (decoder != null && decoder.getServerCommandHeader() != null) {
            return decoder.getServerCommandHeader();
        }

        return "*HBCS";
    }

    private String getManufacturer(Channel channel) {

        SegwayOmniProtocolDecoder decoder = getDecoder(channel);

        if (decoder != null && decoder.getManufacturerCode() != null) {
            return decoder.getManufacturerCode();
        }

        return "NB";
    }

    private ByteBuf formatCommand(Channel channel, Command command, String payload) {

        String uniqueId = getUniqueId(command.getDeviceId());
        String serverHeader = getServerHeader(channel);
        String manufacturer = getManufacturer(channel);

        payload = normalizePayload(uniqueId, payload);

        if (payload == null || payload.isBlank()) {
            return null;
        }

        String body = String.format(
                "%s,%s,%s,%s#\n",
                serverHeader,
                manufacturer,
                uniqueId,
                payload);

        ByteBuf result = Unpooled.buffer();

        result.writeByte(0xFF);
        result.writeByte(0xFF);

        result.writeCharSequence(body, StandardCharsets.US_ASCII);

        return result;
    }

    private String normalizePayload(String uniqueId, String payload) {

        if (payload == null) {
            return null;
        }

        payload = payload.trim();

        if (payload.isEmpty()) {
            return null;
        }

        payload = payload.replace("\r", "").replace("\n", "").trim();

        if (payload.startsWith("FFFF")) {
            payload = payload.substring(4).trim();
        }

        if (payload.startsWith("0xFFFF")) {
            payload = payload.substring(6).trim();
        }

        String[] possiblePrefixes = {
                "*HBCS,NB," + uniqueId + ",",
                "*HBCS,OM," + uniqueId + ",",
                "*SCOS,NB," + uniqueId + ",",
                "*SCOS,OM," + uniqueId + ",",
                "*CMDS,NB," + uniqueId + ",",
                "*CMDS,OM," + uniqueId + ","
        };

        for (String prefix : possiblePrefixes) {
            if (payload.startsWith(prefix)) {
                payload = payload.substring(prefix.length()).trim();
                break;
            }
        }

        if (payload.startsWith("*HBCS,")
                || payload.startsWith("*SCOS,")
                || payload.startsWith("*CMDS,")) {

            String[] parts = payload.split(",", 4);
            if (parts.length == 4) {
                payload = parts[3].trim();
            }
        }

        if (payload.endsWith("#")) {
            payload = payload.substring(0, payload.length() - 1).trim();
        }

        return payload;
    }

    private void setPendingCommand(Channel channel, String pendingCommand) {

        SegwayOmniProtocolDecoder decoder = getDecoder(channel);

        if (decoder != null) {
            decoder.setPendingCommand(pendingCommand);
        }
    }

    private String nextSerial() {
        return String.valueOf(System.currentTimeMillis() / 1000);
    }

    private ByteBuf encodeUnlock(Channel channel, Command command) {
        setPendingCommand(channel, "unlock");
        return formatCommand(
                channel,
                command,
                "R0,0," + KEY_VALID_SECONDS + "," + USER_ID + "," + nextSerial());
    }

    private ByteBuf encodeLock(Channel channel, Command command) {
        setPendingCommand(channel, "lock");
        return formatCommand(
                channel,
                command,
                "R0,1," + KEY_VALID_SECONDS + "," + USER_ID + "," + nextSerial());
    }

    private ByteBuf encodeCustomCommand(Channel channel, Command command) {

        String data = command.getString(Command.KEY_DATA);

        if (data == null || data.isBlank()) {
            return null;
        }

        data = data.trim();

        String normalized = data.toLowerCase(Locale.ROOT);

        return switch (normalized) {

            case "unlock" -> encodeUnlock(channel, command);

            case "lock" -> encodeLock(channel, command);

            case "battery_unlock" -> {
                /*
                 * Temporary default for Segway/Omni G3 scooter/e-bike protocol.
                 * Verify exact C0 payload with real hardware.
                 *
                 * Test manually if needed:
                 * C0,0,10
                 * C0,5,10
                 * C3,51,1
                 */
                yield formatCommand(channel, command, "C0,0,10");
            }

            case "get_location" -> formatCommand(channel, command, "D0");

            case "customcommands", "custom_commands", "custom_command" -> null;

            default -> {
                /*
                 * Raw customer payload.
                 *
                 * Example:
                 * User enters: S6,1,2
                 *
                 * If last received packet was *HBCR,NB:
                 * Server sends: FF FF *HBCS,NB,<IMEI>,S6,1,2#\n
                 *
                 * If last received packet was *SCOR,OM:
                 * Server sends: FF FF *SCOS,OM,<IMEI>,S6,1,2#\n
                 */
                yield formatCommand(channel, command, data);
            }
        };
    }

    @Override
    protected Object encodeCommand(Channel channel, Command command) {

        return switch (command.getType()) {

            case Command.TYPE_CUSTOM -> encodeCustomCommand(channel, command);

            case Command.TYPE_POSITION_SINGLE -> formatCommand(channel, command, "D0");

            case Command.TYPE_POSITION_PERIODIC ->
                    formatCommand(channel, command, "D1," + command.getInteger(Command.KEY_FREQUENCY));

            /*
             * Engine Resume / Start = unlock bike so it can run.
             * Alarm Disarm also maps to unlock.
             */
            case Command.TYPE_ENGINE_RESUME, Command.TYPE_ALARM_DISARM -> encodeUnlock(channel, command);

            /*
             * Engine Stop = lock bike so it stops.
             * Alarm Arm also maps to lock.
             */
            case Command.TYPE_ENGINE_STOP, Command.TYPE_ALARM_ARM -> encodeLock(channel, command);

            default -> null;
        };
    }

}