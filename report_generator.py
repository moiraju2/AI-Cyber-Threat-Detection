<<<<<<< HEAD
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(
    filename,
    scan_type,
    result,
    details
):

    pdf = SimpleDocTemplate(
        filename
    )

    styles = getSampleStyleSheet()

    content = []

    title = Paragraph(
        "AI Cyber Threat Detection Report",
        styles['Title']
    )

    content.append(title)

    content.append(
        Spacer(1, 20)
    )

    content.append(
        Paragraph(
            f"Scan Type: {scan_type}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Result: {result}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Details: {details}",
            styles['BodyText']
        )
    )

=======
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(
    filename,
    scan_type,
    result,
    details
):

    pdf = SimpleDocTemplate(
        filename
    )

    styles = getSampleStyleSheet()

    content = []

    title = Paragraph(
        "AI Cyber Threat Detection Report",
        styles['Title']
    )

    content.append(title)

    content.append(
        Spacer(1, 20)
    )

    content.append(
        Paragraph(
            f"Scan Type: {scan_type}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Result: {result}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Details: {details}",
            styles['BodyText']
        )
    )

>>>>>>> c314c80b1ba667284dad2bd724f11765b1b8ee1f
    pdf.build(content)