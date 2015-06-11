package com.fegor.alfresco.model;

import org.alfresco.service.namespace.QName;

public interface AlfviralModel {
	
	/*
	 * Namespace model
	 */
	public static final String NAMESPACE_ALFVIRAL_CONTENT_MODEL = "http://www.fegorsoft.com/model/alfviral/1.0";

	/*
	 * Aspects
	 */
	public static final QName ASPECT_INFECTED = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "infected");
	public static final QName ASPECT_SCANNED_FROM_COMMAND = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "scanned_from_command");
	public static final QName ASPECT_SCANNED_FROM_CLAMAV = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "scanned_from_clamav");
	public static final QName ASPECT_SCANNED_FROM_VIRUSTOTAL = QName
			.createQName(NAMESPACE_ALFVIRAL_CONTENT_MODEL,
					"scanned_from_virustotal");
	public static final QName ASPECT_SCANNED_FROM_ICAP = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "scanned_from_icap");
	/*
	 * Properties
	 */
	public static final QName PROP_INFECTED_DATE = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "date");
	public static final QName PROP_INFECTED_CLEAN = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "clean");

	public static final QName PROP_VT_RESPONSE_CODE = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "vt_response_code");
	public static final QName PROP_VT_VERBOSE_MSG = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "vt_verbose_msg");
	public static final QName PROP_VT_RESOURCE = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "vt_resource");
	public static final QName PROP_VT_SCAN_ID = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "vt_scan_id");
	public static final QName PROP_VT_PERMALINK = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "vt_permalink");
	public static final QName PROP_VT_SHA256 = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "vt_sha256");
	public static final QName PROP_VT_POSITIVES = QName.createQName(
			NAMESPACE_ALFVIRAL_CONTENT_MODEL, "vt_positives");
}
