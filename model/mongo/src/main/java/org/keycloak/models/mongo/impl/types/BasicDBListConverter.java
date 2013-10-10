package org.keycloak.models.mongo.impl.types;

import java.util.ArrayList;

import com.mongodb.BasicDBList;
import com.mongodb.BasicDBObject;
import org.keycloak.models.mongo.api.types.Converter;
import org.keycloak.models.mongo.api.types.TypeConverter;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class BasicDBListConverter implements Converter<BasicDBList, ArrayList> {

    private final TypeConverter typeConverter;

    public BasicDBListConverter(TypeConverter typeConverter) {
        this.typeConverter = typeConverter;
    }

    @Override
    public ArrayList convertObject(BasicDBList dbList) {
        ArrayList<Object> appObjects = new ArrayList<Object>();
        Class<?> expectedListElementType = null;
        for (Object dbObject : dbList) {

            if (expectedListElementType == null) {
                expectedListElementType = findExpectedListElementType(dbObject);
            }

            appObjects.add(typeConverter.convertDBObjectToApplicationObject(dbObject, expectedListElementType));
        }
        return appObjects;
    }

    @Override
    public Class<? extends BasicDBList> getConverterObjectType() {
        return BasicDBList.class;
    }

    @Override
    public Class<ArrayList> getExpectedReturnType() {
        return ArrayList.class;
    }

    private Class<?> findExpectedListElementType(Object dbObject) {
        if (dbObject instanceof BasicDBObject) {
            BasicDBObject basicDBObject = (BasicDBObject) dbObject;
            String type = (String)basicDBObject.get(ListConverter.OBJECT_TYPE);
            if (type == null) {
                throw new IllegalStateException("Not found OBJECT_TYPE key inside object " + dbObject);
            }
            basicDBObject.remove(ListConverter.OBJECT_TYPE);

            try {
                return Class.forName(type);
            } catch (ClassNotFoundException cnfe) {
                throw new RuntimeException(cnfe);
            }
        } else {
            // Special case (if we have String like "org.keycloak.Gender###MALE" we expect that substring before ### is className
            if (String.class.equals(dbObject.getClass())) {
                String dbObjString = (String)dbObject;
                if (dbObjString.contains(ClassCache.SPLIT)) {
                    String className = dbObjString.substring(0, dbObjString.indexOf(ClassCache.SPLIT));
                    return ClassCache.getInstance().getOrLoadClass(className);
                }
            }

            return dbObject.getClass();
        }
    }
}
