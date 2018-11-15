#!/bin/bash


if [ -z "$SPARK_MASTER_PORT" ]; then
    SPARK_MASTER_PORT=7077
    echo "Master port was not specified, default will be used: 7077"
fi

if [ "$SPARK_MODE" = MASTER ] ; then

    if [ -z "$SPARK_MASTER_WEBUI_PORT" ]; then
        SPARK_MASTER_WEBUI_PORT=8083
        echo "Master web ui port was not specified, default will be used: 8083"
    fi

    /spark/spark-2.4.0/sbin/start-master.sh --host 0.0.0.0 --port $SPARK_MASTER_PORT --webui-port $SPARK_MASTER_WEBUI_PORT; sleep infinity

elif [ "$SPARK_MODE" = WORKER ] ; then

    if [ -z "$SPARK_WORKER_WEBUI_PORT" ]; then
        SPARK_WORKER_WEBUI_PORT=8084
        echo "Worker web ui port was not specified, default will be used: 8084"
    fi

    if [ -z "$SPARK_WORKER_WEBUI_PORT" ]; then
        SPARK_WORKER_WEBUI_PORT=8084
        echo "Worker web ui port was not specified, default will be used: 8084"
    fi

    if [ -z "$SPARK_MASTER_HOST" ]; then
        echo "Please specify master IP by setting MASTER_IP env variable"
        exit 0
    else
        /spark/spark-2.4.0/sbin/start-slave.sh --webui-port $SPARK_WORKER_WEBUI_PORT spark://$SPARK_MASTER_HOST:$SPARK_MASTER_PORT; sleep infinity
    fi
else
    echo "Unknown spark mode"
fi