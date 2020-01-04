configuration TAKSC {
	provides interface TAKS;
}

implementation {
	components TAKSM;
	components LocalTimeMicroC;
	TAKSM.LocalTime -> LocalTimeMicroC;
	TAKS = TAKSM.TAKS;
	components SerialPrintfC;
}
