/*
 * Copyright (C) 2015 Lubomir Rintel
 *
 * Copyright (C) 2008-2011 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2004 Dan Williams
 * Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <libsecret/secret.h>

#include <NetworkManager.h>
#include <nm-vpn-service-plugin.h>
#include <nma-vpn-password-dialog.h>

#define NM_DBUS_SERVICE_STRONGSWAN	"org.freedesktop.NetworkManager.strongswan"

static const SecretSchema network_manager_secret_schema = {
	"org.freedesktop.NetworkManager.Connection",
	SECRET_SCHEMA_DONT_MATCH_NAME,
	{
		{ "connection-uuid", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ "setting-name", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ "setting-key", SECRET_SCHEMA_ATTRIBUTE_STRING },
		{ NULL, 0 },
	}
};

/**
 * Wait for quit input
 */
static void wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}

/**
 * get the connection type
 */
static char* get_connection_type(char *uuid)
{
	GHashTable *data = NULL, *secrets = NULL;
	char *method;

	if (!nm_vpn_service_plugin_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read data and secrets from stdin.\n");
		return NULL;
	}

	method = g_hash_table_lookup (data, "method");
	if (method)
		method = g_strdup(method);

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);

	return method;
}

int main (int argc, char *argv[])
{
	gboolean retry = FALSE, allow_interaction = FALSE;
	gchar *name = NULL, *uuid = NULL, *service = NULL, *pass = NULL;
	GHashTable *secret_attrs;
	GList *secret_list;
	SecretValue *secret_value;
	GOptionContext *context;
	char *agent, *type;
	guint32 minlen = 0;
	GtkWidget *dialog;
	GOptionEntry entries[] = {
		{ "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
		{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &uuid, "UUID of VPN connection", NULL},
		{ "name", 'n', 0, G_OPTION_ARG_STRING, &name, "Name of VPN connection", NULL},
		{ "service", 's', 0, G_OPTION_ARG_STRING, &service, "VPN service type", NULL},
		{ "allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
		{ NULL }
	};

	bindtextdomain(GETTEXT_PACKAGE, NULL);
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
	textdomain(GETTEXT_PACKAGE);

	gtk_init (&argc, &argv);

	context = g_option_context_new ("- strongswan auth dialog");
	g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (uuid == NULL || name == NULL || service == NULL)
	{
		fprintf (stderr, "Have to supply UUID, name, and service\n");
		return 1;
	}

	if (strcmp(service, NM_DBUS_SERVICE_STRONGSWAN) != 0)
	{
		fprintf(stderr, "This dialog only works with the '%s' service\n",
				NM_DBUS_SERVICE_STRONGSWAN);
		return 1;
	}

	type = get_connection_type(uuid);
	if (!type)
	{
		fprintf(stderr, "Connection lookup failed\n");
		return 1;
	}
	if (!strcmp(type, "eap") || !strcmp(type, "key") || !strcmp(type, "psk") ||
		!strcmp(type, "smartcard"))
	{
		secret_attrs = secret_attributes_build(&network_manager_secret_schema,
						       "connection-uuid", uuid,
						       "setting-name", NM_SETTING_VPN_SETTING_NAME,
						       "setting-key", "password",
						       NULL);
		secret_list = secret_service_search_sync(NULL, &network_manager_secret_schema, secret_attrs,
							 SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS,
							 NULL, NULL);

		if (secret_list && secret_list->data) {
			secret_value = secret_item_get_secret(SECRET_ITEM(secret_list->data));
			if (secret_value) {
				pass = g_strdup(secret_value_get(secret_value, NULL));
				secret_value_unref(secret_value);
			}
		}

		g_list_free_full (secret_list, g_object_unref);
		g_hash_table_unref (secret_attrs);

		if ((!pass || retry) && allow_interaction)
		{
			if (!strcmp(type, "eap"))
			{
				dialog = nma_vpn_password_dialog_new(_("VPN password required"),
								     _("EAP password required to establish VPN connection:"),
								     NULL);
			}
			else if (!strcmp(type, "key"))
			{
				dialog = nma_vpn_password_dialog_new(_("VPN password required"),
								     _("Private key decryption password required to establish VPN connection:"),
								     NULL);
			}
			else if (!strcmp(type, "psk"))
			{
				dialog = nma_vpn_password_dialog_new(_("VPN password required"),
								     _("Pre-shared key required to establish VPN connection (min. 20 characters):"),
								     NULL);
				minlen = 20;
			}
			else /* smartcard */
			{
				dialog = nma_vpn_password_dialog_new(_("VPN password required"),
								     _("Smartcard PIN required to establish VPN connection:"),
								     NULL);
			}
			if (pass)
			{
				nma_vpn_password_dialog_set_password(NMA_VPN_PASSWORD_DIALOG(dialog), pass);
			}

			nma_vpn_password_dialog_set_show_password_secondary (NMA_VPN_PASSWORD_DIALOG(dialog), FALSE);
			gtk_widget_show(dialog);
too_short_retry:
			if (!nma_vpn_password_dialog_run_and_block(NMA_VPN_PASSWORD_DIALOG(dialog)))
			{
				return 1;
			}

			pass = g_strdup(nma_vpn_password_dialog_get_password(NMA_VPN_PASSWORD_DIALOG(dialog)));
			if (minlen && strlen(pass) < minlen)
			{
				goto too_short_retry;
			}
		}
		if (pass)
		{
			printf("password\n%s\n", pass);
			g_free(pass);
		}
	}
	else
	{
		agent = getenv("SSH_AUTH_SOCK");
		if (agent)
		{
			printf("agent\n%s\n", agent);
		}
		else
		{
			if (allow_interaction)
			{
				dialog = gtk_message_dialog_new(NULL, 0, GTK_MESSAGE_ERROR,
							  GTK_BUTTONS_OK,
							  _("Configuration uses ssh-agent for authentication, "
							  "but ssh-agent is not running!"));
				gtk_dialog_run (GTK_DIALOG (dialog));
				gtk_widget_destroy (dialog);
			}
		}
	}
	printf("\n\n");
	/* flush output, wait for input */
	fflush(stdout);
	wait_for_quit ();
	return 0;
}
