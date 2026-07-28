/* entry-edit.c — structured editor, M2 (docs/SPEC.md §9, §11.4).
 *
 * Deliberately conservative about the key:value convention (§2.3): every
 * line after the password is edited verbatim in its own row, so files
 * that do not follow the convention round-trip untouched — nothing is
 * parsed apart and reassembled behind the user's back. Editing happens
 * in widget memory; the assembled result goes straight into a secure
 * buffer and to the encrypting writer, never to disk (§7.1).
 *
 * Part of pass-for-linux. GPL-3.0-or-later.
 */
#include "entry-edit.h"

#include <math.h>
#include <string.h>

#include "generate.h"

struct _PassflEntryEdit {
  GtkBox parent_instance;

  GtkWidget *name_row;      /* GtkEntry, visible for new entries only */
  GtkWidget *password;      /* GtkPasswordEntry */
  GtkLevelBar *strength;
  GtkWidget *lines_box;     /* GtkListBox of line rows */
  GtkWidget *gen_length;    /* GtkSpinButton in the generator popover */
  GtkWidget *gen_no_symbols;

  char *name;               /* fixed name when editing, NULL when new */
  gboolean final_newline;   /* reproduce the original convention (§4.6) */
};

G_DEFINE_FINAL_TYPE (PassflEntryEdit, passfl_entry_edit, GTK_TYPE_BOX)

/* --- strength meter -------------------------------------------------------- */

/* Rough entropy estimate: length × log2 of the pool implied by the
 * character classes present. A meter, not a guarantee. */
static double
estimate_bits (const char *pw)
{
  gsize len = strlen (pw);
  guint pool = 0;
  gboolean lower = FALSE, upper = FALSE, digit = FALSE, other = FALSE;

  if (len == 0)
    return 0;
  for (const char *c = pw; *c != '\0'; c++)
    {
      if (g_ascii_islower (*c))
        lower = TRUE;
      else if (g_ascii_isupper (*c))
        upper = TRUE;
      else if (g_ascii_isdigit (*c))
        digit = TRUE;
      else
        other = TRUE;
    }
  pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) +
         (other ? 32 : 0);
  return (double) len * log2 ((double) pool);
}

static void
on_password_changed (PassflEntryEdit *self)
{
  const char *pw = gtk_editable_get_text (GTK_EDITABLE (self->password));

  gtk_level_bar_set_value (self->strength,
                           MIN (estimate_bits (pw), 128.0));
}

/* --- generator ------------------------------------------------------------- */

static void
on_generate (GtkButton *button, gpointer data)
{
  PassflEntryEdit *self = data;
  GError *error = NULL;
  guint length = (guint) gtk_spin_button_get_value_as_int (
      GTK_SPIN_BUTTON (self->gen_length));
  gboolean no_symbols = gtk_check_button_get_active (
      GTK_CHECK_BUTTON (self->gen_no_symbols));
  PassflSecBuf *pw = passfl_generate_password (length, no_symbols, &error);

  (void) button;
  if (pw == NULL)
    {
      g_warning ("generate: %s", error != NULL ? error->message : "?");
      g_clear_error (&error);
      return;
    }
  gtk_editable_set_text (GTK_EDITABLE (self->password), pw->data);
  passfl_secbuf_free (pw);
}

static GtkWidget *
build_generator (PassflEntryEdit *self)
{
  GtkWidget *menu_btn = gtk_menu_button_new ();
  GtkWidget *popover = gtk_popover_new ();
  GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
  GtkWidget *gen_btn = gtk_button_new_with_label ("Generate");
  guint default_len = 25;
  const char *env = g_getenv ("PASSWORD_STORE_GENERATED_LENGTH");

  if (env != NULL && atoi (env) > 0)
    default_len = (guint) atoi (env);

  self->gen_length =
      gtk_spin_button_new_with_range (1, 256, 1);
  gtk_spin_button_set_value (GTK_SPIN_BUTTON (self->gen_length),
                             default_len);
  self->gen_no_symbols = gtk_check_button_new_with_label ("No symbols");

  {
    GtkWidget *len_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *len_label = gtk_label_new ("Length");

    gtk_box_append (GTK_BOX (len_box), len_label);
    gtk_box_append (GTK_BOX (len_box), self->gen_length);
    gtk_box_append (GTK_BOX (box), len_box);
  }
  gtk_box_append (GTK_BOX (box), self->gen_no_symbols);
  gtk_widget_add_css_class (gen_btn, "suggested-action");
  g_signal_connect (gen_btn, "clicked", G_CALLBACK (on_generate), self);
  gtk_box_append (GTK_BOX (box), gen_btn);

  gtk_widget_set_margin_top (box, 10);
  gtk_widget_set_margin_bottom (box, 10);
  gtk_widget_set_margin_start (box, 10);
  gtk_widget_set_margin_end (box, 10);
  gtk_popover_set_child (GTK_POPOVER (popover), box);
  gtk_menu_button_set_popover (GTK_MENU_BUTTON (menu_btn), popover);
  gtk_menu_button_set_icon_name (GTK_MENU_BUTTON (menu_btn),
                                 "view-refresh-symbolic");
  gtk_widget_set_tooltip_text (menu_btn, "Generate a password");
  gtk_widget_set_valign (menu_btn, GTK_ALIGN_CENTER);
  return menu_btn;
}

/* --- metadata line rows ---------------------------------------------------- */

static void
on_remove_line (GtkButton *button, gpointer data)
{
  PassflEntryEdit *self = data;
  GtkWidget *row = gtk_widget_get_ancestor (GTK_WIDGET (button),
                                            GTK_TYPE_LIST_BOX_ROW);

  if (row != NULL)
    gtk_list_box_remove (GTK_LIST_BOX (self->lines_box), row);
}

static void
add_line_row (PassflEntryEdit *self, const char *text)
{
  GtkWidget *row = gtk_list_box_row_new ();
  GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
  GtkWidget *entry = gtk_entry_new ();
  GtkWidget *remove = gtk_button_new_from_icon_name ("list-remove-symbolic");

  gtk_widget_set_hexpand (entry, TRUE);
  gtk_editable_set_text (GTK_EDITABLE (entry), text);
  gtk_widget_add_css_class (entry, "monospace");
  gtk_widget_add_css_class (remove, "flat");
  gtk_widget_set_tooltip_text (remove, "Remove line");
  g_signal_connect (remove, "clicked", G_CALLBACK (on_remove_line), self);

  gtk_widget_set_margin_top (box, 4);
  gtk_widget_set_margin_bottom (box, 4);
  gtk_widget_set_margin_start (box, 6);
  gtk_widget_set_margin_end (box, 6);
  gtk_box_append (GTK_BOX (box), entry);
  gtk_box_append (GTK_BOX (box), remove);
  gtk_list_box_row_set_child (GTK_LIST_BOX_ROW (row), box);
  gtk_list_box_row_set_activatable (GTK_LIST_BOX_ROW (row), FALSE);
  gtk_list_box_append (GTK_LIST_BOX (self->lines_box), row);
}

static void
on_add_line (GtkButton *button, gpointer data)
{
  PassflEntryEdit *self = data;

  (void) button;
  add_line_row (self, "");
}

static const char *
row_text (GtkListBoxRow *row)
{
  GtkWidget *box = gtk_list_box_row_get_child (row);
  GtkWidget *entry = gtk_widget_get_first_child (box);

  return gtk_editable_get_text (GTK_EDITABLE (entry));
}

/* --- public ---------------------------------------------------------------- */

void
passfl_entry_edit_begin (PassflEntryEdit *self, const char *name,
                         PassflEntry *entry)
{
  GtkWidget *row;

  g_return_if_fail (PASSFL_IS_ENTRY_EDIT (self));

  g_clear_pointer (&self->name, g_free);
  while ((row = gtk_widget_get_first_child (self->lines_box)) != NULL)
    gtk_list_box_remove (GTK_LIST_BOX (self->lines_box), row);
  gtk_editable_set_text (GTK_EDITABLE (self->name_row), "");
  gtk_editable_set_text (GTK_EDITABLE (self->password), "");

  if (entry == NULL) /* new entry */
    {
      self->final_newline = TRUE;
      gtk_widget_set_visible (self->name_row, TRUE);
      gtk_widget_grab_focus (self->name_row);
      return;
    }

  self->name = g_strdup (name);
  self->final_newline = passfl_entry_final_newline (entry);
  gtk_widget_set_visible (self->name_row, FALSE);
  gtk_editable_set_text (GTK_EDITABLE (self->password),
                         passfl_entry_password (entry));
  for (guint i = 1; i < passfl_entry_n_lines (entry); i++)
    add_line_row (self, passfl_entry_line (entry, i));
  passfl_entry_free (entry);
  gtk_widget_grab_focus (self->password);
}

const char *
passfl_entry_edit_name (PassflEntryEdit *self)
{
  g_return_val_if_fail (PASSFL_IS_ENTRY_EDIT (self), "");

  if (self->name != NULL)
    return self->name;
  return gtk_editable_get_text (GTK_EDITABLE (self->name_row));
}

gboolean
passfl_entry_edit_is_new (PassflEntryEdit *self)
{
  g_return_val_if_fail (PASSFL_IS_ENTRY_EDIT (self), FALSE);
  return self->name == NULL;
}

PassflSecBuf *
passfl_entry_edit_content (PassflEntryEdit *self)
{
  g_autoptr (GPtrArray) lines = g_ptr_array_new (); /* borrowed strings */
  gsize total = 0;
  PassflSecBuf *buf;
  char *p;

  g_return_val_if_fail (PASSFL_IS_ENTRY_EDIT (self), NULL);

  g_ptr_array_add (lines,
                   (gpointer) gtk_editable_get_text (
                       GTK_EDITABLE (self->password)));
  for (GtkWidget *row = gtk_widget_get_first_child (self->lines_box);
       row != NULL; row = gtk_widget_get_next_sibling (row))
    g_ptr_array_add (lines, (gpointer) row_text (GTK_LIST_BOX_ROW (row)));

  for (guint i = 0; i < lines->len; i++)
    total += strlen (g_ptr_array_index (lines, i)) + 1; /* '\n' */
  if (!self->final_newline && total > 0)
    total--;

  buf = passfl_secbuf_new_sized (total);
  p = buf->data;
  for (guint i = 0; i < lines->len; i++)
    {
      const char *line = g_ptr_array_index (lines, i);
      gsize n = strlen (line);

      memcpy (p, line, n);
      p += n;
      if (i + 1 < lines->len || self->final_newline)
        *p++ = '\n';
    }
  return buf;
}

/* --- boilerplate ------------------------------------------------------------ */

static void
passfl_entry_edit_dispose (GObject *obj)
{
  PassflEntryEdit *self = PASSFL_ENTRY_EDIT (obj);

  g_clear_pointer (&self->name, g_free);
  G_OBJECT_CLASS (passfl_entry_edit_parent_class)->dispose (obj);
}

static void
passfl_entry_edit_class_init (PassflEntryEditClass *klass)
{
  G_OBJECT_CLASS (klass)->dispose = passfl_entry_edit_dispose;
}

static void
passfl_entry_edit_init (PassflEntryEdit *self)
{
  GtkWidget *scrolled = gtk_scrolled_window_new ();
  GtkWidget *clamp = adw_clamp_new ();
  GtkWidget *body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
  GtkWidget *pw_group = adw_preferences_group_new ();
  GtkWidget *pw_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
  GtkWidget *lines_group = adw_preferences_group_new ();
  GtkWidget *add_btn = gtk_button_new_from_icon_name ("list-add-symbolic");

  gtk_orientable_set_orientation (GTK_ORIENTABLE (self),
                                  GTK_ORIENTATION_VERTICAL);

  self->name_row = gtk_entry_new ();
  gtk_entry_set_placeholder_text (GTK_ENTRY (self->name_row),
                                  "Entry name (e.g. social/github)");
  gtk_widget_add_css_class (self->name_row, "monospace");
  gtk_box_append (GTK_BOX (body), self->name_row);

  adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (pw_group),
                                   "Password");
  self->password = gtk_password_entry_new ();
  gtk_password_entry_set_show_peek_icon (GTK_PASSWORD_ENTRY (self->password),
                                         TRUE);
  gtk_widget_set_hexpand (self->password, TRUE);
  g_signal_connect_swapped (self->password, "changed",
                            G_CALLBACK (on_password_changed), self);
  gtk_box_append (GTK_BOX (pw_box), self->password);
  gtk_box_append (GTK_BOX (pw_box), build_generator (self));

  self->strength =
      GTK_LEVEL_BAR (gtk_level_bar_new_for_interval (0, 128));
  gtk_level_bar_add_offset_value (self->strength, GTK_LEVEL_BAR_OFFSET_LOW,
                                  50);
  gtk_level_bar_add_offset_value (self->strength, GTK_LEVEL_BAR_OFFSET_HIGH,
                                  90);
  gtk_level_bar_add_offset_value (self->strength, GTK_LEVEL_BAR_OFFSET_FULL,
                                  128);

  {
    GtkWidget *pw_col = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);

    gtk_box_append (GTK_BOX (pw_col), pw_box);
    gtk_box_append (GTK_BOX (pw_col), GTK_WIDGET (self->strength));
    adw_preferences_group_add (ADW_PREFERENCES_GROUP (pw_group), pw_col);
  }
  gtk_box_append (GTK_BOX (body), pw_group);

  adw_preferences_group_set_title (ADW_PREFERENCES_GROUP (lines_group),
                                   "Details");
  adw_preferences_group_set_description (
      ADW_PREFERENCES_GROUP (lines_group),
      "One line each, stored verbatim — key: value is a convention, "
      "not a rule");
  gtk_widget_add_css_class (add_btn, "flat");
  gtk_widget_set_tooltip_text (add_btn, "Add line");
  g_signal_connect (add_btn, "clicked", G_CALLBACK (on_add_line), self);
  adw_preferences_group_set_header_suffix (
      ADW_PREFERENCES_GROUP (lines_group), add_btn);

  self->lines_box = gtk_list_box_new ();
  gtk_list_box_set_selection_mode (GTK_LIST_BOX (self->lines_box),
                                   GTK_SELECTION_NONE);
  gtk_widget_add_css_class (self->lines_box, "boxed-list");
  adw_preferences_group_add (ADW_PREFERENCES_GROUP (lines_group),
                             self->lines_box);
  gtk_box_append (GTK_BOX (body), lines_group);

  gtk_widget_set_margin_top (body, 18);
  gtk_widget_set_margin_bottom (body, 18);
  gtk_widget_set_margin_start (body, 12);
  gtk_widget_set_margin_end (body, 12);
  adw_clamp_set_child (ADW_CLAMP (clamp), body);
  gtk_scrolled_window_set_child (GTK_SCROLLED_WINDOW (scrolled), clamp);
  gtk_widget_set_vexpand (scrolled, TRUE);
  gtk_box_append (GTK_BOX (self), scrolled);
}

GtkWidget *
passfl_entry_edit_new (void)
{
  return g_object_new (PASSFL_TYPE_ENTRY_EDIT, NULL);
}
