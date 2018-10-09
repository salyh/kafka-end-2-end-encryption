package de.saly.kafka.crypto;

import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.common.serialization.Serializer;

public class CryptoSerde<T> extends Serdes.WrapperSerde<T> {
    public CryptoSerde(Serializer<T> serializer, Deserializer<T> deserializer) {
        super(serializer, deserializer);
    }
}
