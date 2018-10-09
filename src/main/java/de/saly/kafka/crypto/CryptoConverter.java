package de.saly.kafka.crypto;

import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.connect.data.Schema;
import org.apache.kafka.connect.data.SchemaAndValue;
import org.apache.kafka.connect.errors.DataException;
import org.apache.kafka.connect.storage.Converter;
import org.apache.kafka.connect.storage.ConverterType;
import org.apache.kafka.connect.storage.StringConverterConfig;

import java.util.HashMap;
import java.util.Map;


public class CryptoConverter implements Converter {

    private final EncryptingSerializer serializer = new EncryptingSerializer();
    private final DecryptingDeserializer deserializer = new DecryptingDeserializer();

    public void configure(Map<String, ?> configs) {
        StringConverterConfig conf = new StringConverterConfig(configs);
        String encoding = conf.encoding();

        Map<String, Object> serializerConfigs = new HashMap(configs);
        Map<String, Object> deserializerConfigs = new HashMap(configs);
        serializerConfigs.put("serializer.encoding", encoding);
        deserializerConfigs.put("deserializer.encoding", encoding);

        boolean isKey = conf.type() == ConverterType.KEY;
        serializer.configure(serializerConfigs, isKey);
        deserializer.configure(deserializerConfigs, isKey);
    }

    @Override
    public void configure(Map<String, ?> configs, boolean isKey) {
        Map<String, Object> conf = new HashMap(configs);
        conf.put(StringConverterConfig.TYPE_CONFIG, isKey ? ConverterType.KEY.getName() : ConverterType.VALUE.getName());
        configure(conf);
    }

    @Override
    public byte[] fromConnectData(String topic, Schema schema, Object value) {
        try {
            return serializer.serialize(topic, value == null ? null : value.toString());
        } catch (SerializationException e) {
            throw new DataException("Failed to serialize to a string: ", e);
        }
    }

    @Override
    public SchemaAndValue toConnectData(String topic, byte[] value) {
        try {
            return new SchemaAndValue(Schema.OPTIONAL_STRING_SCHEMA, deserializer.deserialize(topic, value));
        } catch (SerializationException e) {
            throw new DataException("Failed to deserialize string: ", e);
        }
    }
}
