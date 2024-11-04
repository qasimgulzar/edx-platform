# Generated by Django 2.2.12 on 2020-05-21 00:22
#
# Manually modified to collate some fields as utf8_bin for case sensitive
# matching.

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
import opaque_keys.edx.django.models
from django.conf import settings
from django.db import connection

def run_before_migrate(apps, schema_editor):
    if connection.vendor == 'mysql':
        # MySQL: utf8_bin collation
        schema_editor.execute('ALTER TABLE learning_sequences_learningcontext MODIFY context_key VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_bin;')
        schema_editor.execute('ALTER TABLE learning_sequences_coursesection MODIFY usage_key VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_bin;')
        schema_editor.execute('ALTER TABLE learning_sequences_learningsequence MODIFY usage_key VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_bin;')
    elif connection.vendor == 'postgresql':
        # PostgreSQL: Use binary collation
        schema_editor.execute('ALTER TABLE learning_sequences_learningcontext ALTER COLUMN context_key TYPE VARCHAR(255) COLLATE "C";')
        schema_editor.execute('ALTER TABLE learning_sequences_coursesection ALTER COLUMN usage_key TYPE VARCHAR(255) COLLATE "C";')
        schema_editor.execute('ALTER TABLE learning_sequences_learningsequence ALTER COLUMN usage_key TYPE VARCHAR(255) COLLATE "C";')
class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CourseSection',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('ordering', models.PositiveIntegerField()),
                ('usage_key', opaque_keys.edx.django.models.UsageKeyField(max_length=255)),
                ('title', models.CharField(max_length=1000)),
                ('hide_from_toc', models.BooleanField(default=False)),
                ('visible_to_staff_only', models.BooleanField(default=False)),
                ('created', model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name='created')),
                ('modified', model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name='modified')),
            ],
        ),
        migrations.CreateModel(
            name='CourseSectionSequence',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('ordering', models.PositiveIntegerField()),
                ('hide_from_toc', models.BooleanField(default=False)),
                ('visible_to_staff_only', models.BooleanField(default=False)),
                ('created', model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name='created')),
                ('modified', model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name='modified')),
            ],
        ),
        migrations.CreateModel(
            name='LearningContext',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('context_key', opaque_keys.edx.django.models.LearningContextKeyField(db_index=True, max_length=255, unique=True)),
                ('title', models.CharField(max_length=255)),
                ('published_at', models.DateTimeField()),
                ('published_version', models.CharField(max_length=255)),
                ('created', model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name='created')),
                ('modified', model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name='modified')),
            ],
        ),
        migrations.CreateModel(
            name='LearningSequence',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('learning_context', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sequences', to='learning_sequences.LearningContext')),
                ('usage_key', opaque_keys.edx.django.models.UsageKeyField(max_length=255)),
                ('title', models.CharField(max_length=1000)),
                ('created', model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name='created')),
                ('modified', model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name='modified')),
            ],
        ),
        migrations.AddIndex(
            model_name='learningcontext',
            index=models.Index(fields=['-published_at'], name='learning_se_publish_62319b_idx'),
        ),
        migrations.AddField(
            model_name='coursesectionsequence',
            name='learning_context',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='section_sequences', to='learning_sequences.LearningContext'),
        ),
        migrations.AddField(
            model_name='coursesectionsequence',
            name='section',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='learning_sequences.CourseSection'),
        ),
        migrations.AddField(
            model_name='coursesectionsequence',
            name='sequence',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='learning_sequences.LearningSequence'),
        ),
        migrations.AddField(
            model_name='coursesection',
            name='learning_context',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sections', to='learning_sequences.LearningContext'),
        ),
        migrations.AlterUniqueTogether(
            name='learningsequence',
            unique_together={('learning_context', 'usage_key')},
        ),
        migrations.AlterUniqueTogether(
            name='coursesectionsequence',
            unique_together={('learning_context', 'ordering')},
        ),
        migrations.AlterUniqueTogether(
            name='coursesection',
            unique_together={('learning_context', 'usage_key')},
        ),
        migrations.AlterIndexTogether(
            name='coursesection',
            index_together={('learning_context', 'ordering')},
        ),

        # Custom code: Convert columns to utf8_bin for MySQL or the equivalent for PostgreSQL
        migrations.RunPython(run_before_migrate),
    ]
