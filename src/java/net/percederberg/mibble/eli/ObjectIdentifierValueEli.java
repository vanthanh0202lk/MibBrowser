package net.percederberg.mibble.eli;
import net.percederberg.mibble.*;
import net.percederberg.mibble.value.*;

public class ObjectIdentifierValueEli {

    public ObjectIdentifierValue extractOid(MibSymbol symbol) {
        if (symbol instanceof MibValueSymbol) {
            MibValue value = ((MibValueSymbol) symbol).getValue();
            if (value instanceof ObjectIdentifierValue) {
                return (ObjectIdentifierValue) value;
            }
        }
        return null;
    }
}
