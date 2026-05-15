/*
 * Copyright 2018 - 2024 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.traccar.protocol;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.traccar.BaseProtocolDecoder;
import org.traccar.NetworkMessage;
import org.traccar.Protocol;
import org.traccar.helper.DateBuilder;
import org.traccar.helper.Parser;
import org.traccar.helper.PatternBuilder;
import org.traccar.model.Position;
import org.traccar.session.DeviceSession;

import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.regex.Pattern;

public class SegwayOmniProtocolDecoder extends BaseProtocolDecoder {

    private String pendingCommand;

    /*
     * Learned from incoming packet.
     *
     * Examples:
     * Device -> server: *HBCR,NB,...
     * Server -> device: *HBCS,NB,...
     *
     * Device -> server: *SCOR,OM,...
     * Server -> device: *SCOS,OM,...
     *
     * Device -> server: *CMDR,OM,...
     * Server -> device: *CMDS,OM,...
     */
    private String serverCommandHeader = "*HBCS";
    private String manufacturerCode = "NB";

    public void setPendingCommand(String pendingCommand) {
        this.pendingCommand = pendingCommand;
    }

    public String getServerCommandHeader() {
        return serverCommandHeader;
    }

    public String getManufacturerCode() {
        return manufacturerCode;
    }

    public void setCommandEnvelope(String incomingHeader, String manufacturer) {

        if (incomingHeader != null) {
            serverCommandHeader = switch (incomingHeader) {
                case "*HBCR" -> "*HBCS";
                case "*SCOR" -> "*SCOS";
                case "*CMDR" -> "*CMDS";
                default -> serverCommandHeader;
            };
        }

        if (manufacturer != null && !manufacturer.isBlank()) {
            manufacturerCode = manufacturer;
        }
    }

    public SegwayOmniProtocolDecoder(Protocol protocol) {
        super(protocol);
    }

    private static final Pattern PATTERN = new PatternBuilder()
            .text("*")
            .expression("....,")
            .expression("..,")                   // vendor
            .number("d{15},")                    // imei
            .number("d{12},").optional()         // time
            .expression("..,")
            .number("d{1,3},")                   // type location flags / reserved
            .number("(dd)(dd)(dd).d+,")          // time (hhmmss)
            .expression("([AV]),")               // validity
            .number("(dd)(dd.d+),")              // latitude
            .expression("([NS]),")
            .number("(d{2,3})(dd.d+),")          // longitude
            .expression("([EW]),")
            .number("(d+),")                     // satellites
            .number("(d+.d+),")                  // hdop
            .number("(dd)(dd)(dd),")             // date (ddmmyy)
            .number("(-?d+.?d*),")               // altitude
            .expression(".,")                    // height unit
            .expression(".#")                    // mode
            .compile();

    private String currentProtocolTime() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyMMddHHmmss"));
    }

    private ByteBuf buildServerCommand(String header, String vendor, String imei, String payload) {

        String body = String.format("%s,%s,%s,%s#\n", header, vendor, imei, payload);

        ByteBuf response = Unpooled.buffer();

        // Binary 0xFFFF prefix required by Omni / Segway protocol.
        response.writeByte(0xFF);
        response.writeByte(0xFF);

        response.writeCharSequence(body, StandardCharsets.US_ASCII);

        return response;
    }

    private void sendServerCommand(
            Channel channel, SocketAddress remoteAddress, String header, String vendor, String imei, String payload) {

        if (channel == null) {
            return;
        }

        ByteBuf response = buildServerCommand(header, vendor, imei, payload);
        channel.writeAndFlush(new NetworkMessage(response, remoteAddress));
    }

    private void sendAck(
            Channel channel, SocketAddress remoteAddress,
            String incomingHeader, String vendor, String imei, String time, String type) {

        if (channel == null) {
            return;
        }

        String serverHeader = switch (incomingHeader) {
            case "*HBCR" -> "*HBCS";
            case "*SCOR" -> "*SCOS";
            case "*CMDR" -> "*CMDS";
            default -> serverCommandHeader;
        };

        /*
         * HBC / SCO style:
         * *HBCS,NB,<imei>,L0#
         *
         * CMD style horseshoe lock:
         * *CMDS,OM,<imei>,<time>,Re,L0#
         */
        String payload;
        if ("*CMDS".equals(serverHeader)) {
            String ackTime = time != null ? time : currentProtocolTime();
            payload = ackTime + ",Re," + type;
        } else {
            payload = type;
        }

        sendServerCommand(channel, remoteAddress, serverHeader, vendor, imei, payload);
    }

    private boolean needsAck(String type) {
        return type.matches("L0|L1|D0|W0|W1|E0|E1");
    }

    private Integer readInt(String[] values, int index) {
        if (index >= values.length || values[index] == null || values[index].isBlank()) {
            return null;
        }
        try {
            return Integer.parseInt(values[index]);
        } catch (NumberFormatException error) {
            return null;
        }
    }

    private Double readDouble(String[] values, int index) {
        if (index >= values.length || values[index] == null || values[index].isBlank()) {
            return null;
        }
        try {
            return Double.parseDouble(values[index]);
        } catch (NumberFormatException error) {
            return null;
        }
    }

    @Override
    protected Object decode(
            Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {

        String sentence = ((String) msg).trim();

        // Safety: if a packet somehow contains leading FF characters, remove them.
        while (!sentence.isEmpty() && sentence.charAt(0) == 0xFF) {
            sentence = sentence.substring(1);
        }

        String cleanSentence = sentence.replaceAll("#$", "");
        String[] values = cleanSentence.split(",", -1);

        if (values.length < 4) {
            return null;
        }

        int index = 0;

        String header = values[index++];
        String vendor = values[index++];
        String imei = values[index++];

        setCommandEnvelope(header, vendor);

        DeviceSession deviceSession = getDeviceSession(channel, remoteAddress, imei);
        if (deviceSession == null) {
            return null;
        }

        String time;
        if (index < values.length && values[index].length() == 12 && values[index].matches("\\d{12}")) {
            time = values[index++];
        } else {
            time = null;
        }

        if (index >= values.length) {
            return null;
        }

        String type = values[index++];

        /*
         * ACK first.
         * Important because device can resend L0/L1/D0/W0/E0 if it does not receive server confirmation.
         */
        if (needsAck(type)) {
            sendAck(channel, remoteAddress, header, vendor, imei, time, type);
        }

        /*
         * R0 response handling:
         *
         * Incoming:
         * *HBCR,NB,<imei>,R0,<operation>,<key>,<userId>,<serial>#
         *
         * If pending command is unlock:
         * Send:
         * *HBCS,NB,<imei>,L0,<key>,<userId>,<serial>#
         *
         * If pending command is lock:
         * Send:
         * *HBCS,NB,<imei>,L1,<key>#
         */
        if ("R0".equals(type) && pendingCommand != null) {

            if (values.length >= index + 4) {

                String operation = values[index];
                String key = values[index + 1];
                String userId = values[index + 2];
                String serial = values[index + 3];

                if ("unlock".equalsIgnoreCase(pendingCommand)) {
                    sendServerCommand(
                            channel,
                            remoteAddress,
                            serverCommandHeader,
                            manufacturerCode,
                            imei,
                            "L0," + key + "," + userId + "," + serial);
                } else if ("lock".equalsIgnoreCase(pendingCommand)) {
                    sendServerCommand(
                            channel,
                            remoteAddress,
                            serverCommandHeader,
                            manufacturerCode,
                            imei,
                            "L1," + key);
                }

                pendingCommand = null;
            }
        }

        /*
         * D0 is GPS.
         * Other D commands can exist, but current GPS parser is for D0-style location payload.
         */
        if ("D0".equals(type)) {

            Parser parser = new Parser(PATTERN, sentence);
            if (!parser.matches()) {
                return null;
            }

            Position position = new Position(getProtocolName());
            position.setDeviceId(deviceSession.getDeviceId());

            DateBuilder dateBuilder = new DateBuilder()
                    .setTime(parser.nextInt(), parser.nextInt(), parser.nextInt());

            position.setValid(parser.next().equals("A"));
            position.setLatitude(parser.nextCoordinate());
            position.setLongitude(parser.nextCoordinate());

            position.set(Position.KEY_SATELLITES, parser.nextInt());
            position.set(Position.KEY_HDOP, parser.nextDouble());

            dateBuilder.setDateReverse(parser.nextInt(), parser.nextInt(), parser.nextInt());
            position.setTime(dateBuilder.getDate());

            position.setAltitude(parser.nextDouble());

            return position;
        }

        /*
         * Non-GPS packets become event/status/result positions.
         */
        Position position = new Position(getProtocolName());
        position.setDeviceId(deviceSession.getDeviceId());

        getLastLocation(position, null);

        switch (type) {

            case "Q0" -> {
                /*
                 * Common HBC Q0:
                 * Q0,<lockVoltage>,<vehicleBatteryLevel>,<rssi>,...
                 *
                 * Common horseshoe Q0:
                 * Q0,<lockVoltage>
                 */
                Integer lockVoltage = readInt(values, index);
                if (lockVoltage != null) {
                    position.set(Position.KEY_BATTERY, lockVoltage / 100.0);
                    index++;
                }

                Integer vehicleBattery = readInt(values, index);
                if (vehicleBattery != null) {
                    position.set(Position.KEY_BATTERY_LEVEL, vehicleBattery);
                    index++;
                }

                Integer rssi = readInt(values, index);
                if (rssi != null) {
                    position.set(Position.KEY_RSSI, rssi);
                }
            }

            case "H0" -> {
                /*
                 * HBC H0:
                 * H0,<lockStatus>,<lockVoltage>,<rssi>,<vehicleBattery>,<charging>
                 *
                 * Horseshoe H0:
                 * H0,<lockStatus>,<lockVoltage>,<rssi>
                 */
                Integer lockStatus = readInt(values, index);
                if (lockStatus != null) {
                    position.set(Position.KEY_BLOCKED, lockStatus > 0);
                    position.set("lockStatus", lockStatus > 0 ? "locked" : "unlocked");
                    index++;
                }

                Integer lockVoltage = readInt(values, index);
                if (lockVoltage != null) {
                    position.set(Position.KEY_BATTERY, lockVoltage / 100.0);
                    index++;
                }

                Integer rssi = readInt(values, index);
                if (rssi != null) {
                    position.set(Position.KEY_RSSI, rssi);
                    index++;
                }

                Integer vehicleBattery = readInt(values, index);
                if (vehicleBattery != null) {
                    position.set(Position.KEY_BATTERY_LEVEL, vehicleBattery);
                    index++;
                }

                Integer charging = readInt(values, index);
                if (charging != null) {
                    position.set(Position.KEY_CHARGE, charging > 0);
                }
            }

            case "W0" -> {
                Integer alarmType = readInt(values, index);
                if (alarmType != null) {
                    switch (alarmType) {
                        case 1 -> position.addAlarm(Position.ALARM_MOVEMENT);
                        case 2 -> position.addAlarm(Position.ALARM_FALL_DOWN);
                        case 12 -> position.addAlarm(Position.ALARM_LOW_BATTERY);
                        default -> position.set("alarm", alarmType);
                    }
                }
            }

            case "W1" -> {
                Integer alarmType = readInt(values, index);
                if (alarmType != null) {
                    position.set("alarmDismissed", alarmType);
                }
            }

            case "E0" -> {
                position.addAlarm(Position.ALARM_FAULT);
                Integer error = readInt(values, index);
                if (error != null) {
                    position.set("error", error);
                }
            }

            case "E1" -> {
                Integer error = readInt(values, index);
                if (error != null) {
                    position.set("errorCleared", error);
                }
            }

            case "L0" -> {
                /*
                 * Unlock result:
                 * L0,<result>,<userId>,<serial>
                 *
                 * result 0 = success.
                 */
                Integer result = readInt(values, index);
                if (result != null) {
                    position.set(Position.KEY_RESULT, result);
                    position.set("lockStatus", result == 0 ? "unlocked" : "unlockFailed");
                    position.set(Position.KEY_BLOCKED, result != 0);
                }

                String[] remaining = Arrays.copyOfRange(values, index, values.length);
                position.set("commandResult", String.join(",", remaining));
            }

            case "L1" -> {
                /*
                 * Lock result:
                 * L1,<result>,<userId>,<serial>,<rideTime>
                 *
                 * result 0 = success.
                 */
                Integer result = readInt(values, index);
                if (result != null) {
                    position.set(Position.KEY_RESULT, result);
                    position.set("lockStatus", result == 0 ? "locked" : "lockFailed");
                    position.set(Position.KEY_BLOCKED, result == 0);
                }

                if (values.length > index + 3) {
                    Integer rideTime = readInt(values, index + 3);
                    if (rideTime != null) {
                        position.set("rideTime", rideTime);
                    }
                }

                String[] remaining = Arrays.copyOfRange(values, index, values.length);
                position.set("commandResult", String.join(",", remaining));
            }

            case "S6" -> {
                /*
                 * Vehicle data:
                 * S6,<battery>,<mode>,<speed>,<mileage>,...
                 */
                Integer batteryLevel = readInt(values, index);
                if (batteryLevel != null) {
                    position.set(Position.KEY_BATTERY_LEVEL, batteryLevel);
                }

                Integer mode = readInt(values, index + 1);
                if (mode != null) {
                    position.set("mode", mode);
                }

                Double speed = readDouble(values, index + 2);
                if (speed != null) {
                    position.setSpeed(speed);
                }

                String[] remaining = Arrays.copyOfRange(values, index, values.length);
                position.set(Position.KEY_RESULT, String.join(",", remaining));
            }

            case "S1", "R0", "S4", "S5", "S7", "S8", "V0", "G0", "G3", "K0", "K1", "I0", "M0", "C0", "C1", "C2", "C3", "C4", "L5" -> {
                String[] remaining = Arrays.copyOfRange(values, index, values.length);
                position.set(Position.KEY_RESULT, String.join(",", remaining));
            }

            default -> {
                String[] remaining = Arrays.copyOfRange(values, index, values.length);
                position.set(Position.KEY_RESULT, String.join(",", remaining));
                position.set("type", type);
            }
        }

        return !position.getAttributes().isEmpty() ? position : null;
    }

}