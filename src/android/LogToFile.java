package android;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.rolling.TimeBasedRollingPolicy;

public class LogToFile {
	private static final String PATTERN = "%5p [] \\(%d{dd/MM/yyyy HH:mm:ss}\\) [%thread] \\(%logger{36}\\) - %msg%n";
	
	public Logger configureLogger(String path) {
		Logger logger = (Logger) LoggerFactory.getLogger(FingerprintAuth.class);

		PatternLayoutEncoder logEncoder = new PatternLayoutEncoder();
		logEncoder.setContext(logger.getLoggerContext());
		logEncoder.setPattern(PATTERN);
		logEncoder.start();

		RollingFileAppender<ILoggingEvent> logFileAppender = new RollingFileAppender<ILoggingEvent>();
		logFileAppender.setContext(logger.getLoggerContext());
		logFileAppender.setName("FILE");
		logFileAppender.setEncoder(logEncoder);
		logFileAppender.setAppend(true);

		TimeBasedRollingPolicy<ILoggingEvent> logFilePolicy = new TimeBasedRollingPolicy<ILoggingEvent>();
		logFilePolicy.setContext(logger.getLoggerContext());
		logFilePolicy.setParent(logFileAppender);
		logFilePolicy.setFileNamePattern(path + "/" + "FingerprintAuth.%d{yyyy-MM-dd}.log");
		logFilePolicy.setMaxHistory(2);
		logFilePolicy.setCleanHistoryOnStart(true);
		logFilePolicy.start();

		logFileAppender.setRollingPolicy(logFilePolicy);
		logFileAppender.start();

		logger.addAppender(logFileAppender);
		logger.setLevel(Level.DEBUG);
		
		return logger;
	}
}
